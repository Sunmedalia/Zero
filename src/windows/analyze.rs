//! Request validation and the public analysis entry points.
use super::*;

pub fn analyze(
    image: &Image,
    request: &Request<'_>,
    dump: Option<&DumpOptions>,
    options: &Options,
    job: &Job,
) -> Result<Outcome> {
    if image.windows_container.as_ref().is_some_and(|m| {
        m.virtual_memory
            || m.kernel_virtual
            || image.segments.is_empty()
            || request.plugin == Plugin::WinCrashinfo
    }) {
        ensure!(
            options.pagefiles.is_empty() && options.swapfile.is_none(),
            "此容器没有可验证的内核分页索引，不接受分页附件"
        );
        return container::analyze(image, request, dump, options, job).map(Outcome::Ready);
    }
    validate_request(request, dump, options)?;
    let symbols =
        windows_symbols::resolve(request.symbols, image, request.cache, request.network, job)?;
    let symbols: Vec<_> = symbols.into_iter().map(std::sync::Arc::new).collect();
    analyze_resolved(image, request, dump, options, job, &symbols)
}
pub(crate) fn validate_request(
    request: &Request<'_>,
    dump: Option<&DumpOptions>,
    options: &Options,
) -> Result<()> {
    if request.plugin.is_dump() {
        dump.context("Windows 转储需要 PID 和输出目录")?
            .validate(request.plugin)?;
    } else if let Some(dump) = dump.filter(|_| request.plugin.accepts_dump()) {
        dump.validate(request.plugin)?;
    } else {
        ensure!(dump.is_none(), "分析插件不接受转储参数");
    }
    ensure!(
        request.plugin == Plugin::WinPrintkey
            || (matches!(
                request.plugin,
                Plugin::WinAutoruns | Plugin::WinUserassist | Plugin::WinUserAssistV4
            ) && options.key.is_empty())
            || (options.hive.is_none() && options.key.is_empty()),
        "hive/key 仅用于 windows.printkey"
    );
    if request.plugin == Plugin::WinPrintkey {
        ensure!(options.hive.is_some(), "windows.printkey 需要 --hive 地址");
    }
    crate::analysis::validate_pattern(request.plugin, options)?;
    ensure!(
        options.pid.is_none()
            || request.plugin == Plugin::WinMemmap
            || request.plugin.descriptor().columns.contains(&"PID"),
        "此插件不支持 PID 筛选"
    );
    Ok(())
}
pub(crate) fn analyze_resolved(
    image: &Image,
    request: &Request<'_>,
    dump: Option<&DumpOptions>,
    options: &Options,
    job: &Job,
    symbols: &[std::sync::Arc<Isf>],
) -> Result<Outcome> {
    let isf = if let Some(choice) = request.choice {
        symbols
            .iter()
            .find(|s| s.label == choice)
            .context("所选 Windows 符号不在精确匹配候选中")?
    } else {
        if symbols.len() > 1 {
            return Ok(Outcome::Choose(
                symbols.iter().map(|s| s.label.clone()).collect(),
            ));
        }
        symbols.at(0)?
    };
    let arch = Architecture::from_isf(isf)?;
    ensure!(
        options.arch == Architecture::Auto || options.arch == arch,
        "显式架构与符号不一致"
    );
    if let Some(hiber) = &image.hibernation {
        ensure!(
            arch.pointer_size() == hiber.info.pointer_size,
            "休眠容器与符号指针宽度不一致"
        );
    }
    let (root, base) = discover(image, isf, job)?;
    let mut sources = paging::Sources::open(options, job)?;
    let mut engine = Windows {
        vm: Memory::new(image, root, isf, None),
        base,
        pdb: PdbIdentity::from_isf(isf)?,
    };
    sources.configure_kernel(&engine)?;
    engine.vm.sources = Some(&sources);
    let key = store::key(
        &image.digest,
        &isf.digest,
        &format!(
            "{}:{:?}:{:?}:{}:{}:pids={:?}:maxsize={:?}",
            request.plugin.name(),
            options.pid,
            options.hive,
            sources.cache_identity(),
            format_args!(
                "{}:{}:{:x}",
                options.key,
                options.pattern.as_deref().unwrap_or_default(),
                sha2::Sha256::digest(network::LAYOUTS.as_bytes())
            ),
            options.pids,
            options.maxsize
        ),
    );
    let cached = if request.use_cache
        && dump.is_none()
        && !request.plugin.is_dump()
        && !matches!(
            request.plugin,
            Plugin::WinPESymbols
                | Plugin::WinSuspendedThreads
                | Plugin::WinDebugRegisters
                | Plugin::WinUnhookedSystemCalls
                | Plugin::WinSkeletonKeyCheck
                | Plugin::WinTruecryptPassphrase
                | Plugin::WinStrings
                | Plugin::WinDirectSystemCalls
                | Plugin::WinIndirectSystemCalls
        ) {
        if request.plugin == Plugin::WinDriverIrp {
            dispatch::load_cached(request.cache, &key, request.network, job)?
        } else {
            store::load(request.cache, &key).or_else(|| store::load_partial(request.cache, &key))
        }
    } else {
        None
    };
    if let Some(r) = cached {
        sources.validate()?;
        job.mark_cached();
        let owner = store::Owner::new(&image.digest, request.image);
        store::adopt(request.cache, &key, &owner, &r, job);
        job.report(store::cache_message(&r));
        return Ok(Outcome::Ready(r));
    }
    let mut result = if let Some(dump) = dump {
        engine.run_dump(request.plugin, dump, job)?
    } else if request.plugin == Plugin::WinDebugRegisters {
        engine.debug_registers(Some((request.cache, request.network)), job)?
    } else if request.plugin == Plugin::WinSuspendedThreads {
        engine.suspended_threads(Some((request.cache, request.network)), job)?
    } else if request.plugin == Plugin::WinUnhookedSystemCalls {
        engine.unhooked_system_calls(Some((request.cache, request.network)), job)?
    } else if request.plugin == Plugin::WinSkeletonKeyCheck {
        engine.skeleton_key(Some((request.cache, request.network)), job)?
    } else if request.plugin == Plugin::WinPESymbols {
        engine.pe_symbols(options, Some((request.cache, request.network)), job)?
    } else if request.plugin == Plugin::WinDriverIrp {
        engine.driver_irp_with_symbols(job, Some((request.cache, request.network)))?
    } else if request.plugin == Plugin::WinNetscan {
        engine.netscan(job, Some((request.cache, request.network)))?
    } else if request.plugin == Plugin::WinNetstat {
        engine.netstat(job, Some((request.cache, request.network)))?
    } else {
        engine.run(request.plugin, options, job)?
    };
    if let Some(pid) = options.pid
        && !request.plugin.accepts_pid_list()
        && let Some(index) = result.columns.iter().position(|c| c == "PID")
    {
        result.rows.retain(|row| row[index] == pid.to_string());
    }
    sources.validate()?;
    *result.kernel_identity.key_mut("paging_sources")? = sources.manifest()?;
    let compressed = sources.compressed_evidence()?;
    if !compressed.as_array().is_none_or(Vec::is_empty) {
        Windows::issue(
            &mut result,
            "压缩 store",
            "此恢复路径经合成测试验证，尚未完成真实镜像对照",
        );
    }
    *result.kernel_identity.key_mut("compressed_pages")? = compressed;
    if let Some(hiber) = image.hibernation.as_ref() {
        *result.kernel_identity.key_mut("hibernation")? = serde_json::to_value(&hiber.info)?;
        Windows::issue(
            &mut result,
            "休眠文件",
            if hiber.info.hiberboot == Some(true) {
                "Fast Startup 保存内核会话，用户会话页面可能缺失；此容器路径目前仅有合成验证"
            } else {
                "仅包含休眠文件保存的物理页；此容器路径目前仅有合成验证"
            },
        );
        result.diagnostics.extend(hiber.info.diagnostics.clone());
    }
    job.check()?;
    if request.use_cache
        && !matches!(
            request.plugin,
            Plugin::WinPESymbols
                | Plugin::WinSuspendedThreads
                | Plugin::WinDebugRegisters
                | Plugin::WinUnhookedSystemCalls
                | Plugin::WinSkeletonKeyCheck
                | Plugin::WinTruecryptPassphrase
                | Plugin::WinStrings
                | Plugin::WinDirectSystemCalls
                | Plugin::WinIndirectSystemCalls
        )
        && dump.is_none()
        && !request.plugin.is_dump()
        && (request.plugin != Plugin::WinDriverIrp
            || dispatch::dependencies_match(&result, request.cache, request.network, job)?)
    {
        store::save_any(
            request.cache,
            &key,
            &store::Owner::new(&image.digest, request.image),
            &result,
            job,
        )?;
    }
    Ok(Outcome::Ready(result))
}
