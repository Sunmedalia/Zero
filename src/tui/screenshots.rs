//! Offline figure generation shares the production state machine and Buffer.
use super::*;
use ratatui::{backend::TestBackend, buffer::Buffer};
use std::{fmt::Write, path::Path};

fn settle(app: &mut App) -> Result<()> {
    let started = Instant::now();
    while app.job.is_some() {
        app.drain();
        if started.elapsed() > Duration::from_secs(600) {
            app.cancel();
            app.finish_worker();
            anyhow::bail!("截图任务超时");
        }
        thread::sleep(Duration::from_millis(10));
    }
    anyhow::ensure!(!app.status.starts_with("失败"), "{}", app.status);
    Ok(())
}
fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
fn color(value: Color) -> String {
    match value {
        Color::Rgb(r, g, b) => format!("#{r:02x}{g:02x}{b:02x}"),
        Color::Black => "#000000".into(),
        Color::White => "#ffffff".into(),
        _ => "#97a6b8".into(),
    }
}
fn svg(buffer: &Buffer, title: &str) -> String {
    let width = buffer.area.width;
    let height = buffer.area.height;
    let mut output = format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"{}\" height=\"{}\" viewBox=\"0 0 {} {}\" role=\"img\" aria-label=\"{}\"><title>{}</title>\n",
        width as f64 * 8.4 + 28.0,
        height * 18 + 58,
        width as f64 * 8.4 + 28.0,
        height * 18 + 58,
        escape(title),
        escape(title)
    );
    let _ = writeln!(
        output,
        "<rect width=\"100%\" height=\"100%\" rx=\"10\" fill=\"{}\"/><g font-family=\"ui-monospace, 'SFMono-Regular', Menlo, Consolas, 'Noto Sans Mono CJK SC', monospace\" font-size=\"14\" xml:space=\"preserve\">",
        color(buffer[(0, 0)].bg)
    );
    let _ = writeln!(
        output,
        "<text x=\"14\" y=\"23\" fill=\"{}\">{}</text>",
        color(buffer[(0, 0)].fg),
        escape(title)
    );
    for y in 0..height {
        let mut x = 0;
        while x < width {
            let cell = &buffer[(x, y)];
            let mut end = x;
            while end < width {
                let next = &buffer[(end, y)];
                if next.fg != cell.fg || next.bg != cell.bg || next.modifier != cell.modifier {
                    break;
                }
                end += unicode_width::UnicodeWidthStr::width(next.symbol()).max(1) as u16;
            }
            let px = 14.0 + x as f64 * 8.4;
            let py = 44 + y * 18;
            let _ = writeln!(
                output,
                "<rect x=\"{px:.1}\" y=\"{py}\" width=\"{:.1}\" height=\"18\" fill=\"{}\"/>",
                (end - x) as f64 * 8.4,
                color(cell.bg)
            );
            let weight = if cell.modifier.contains(Modifier::BOLD) {
                " font-weight=\"700\""
            } else {
                ""
            };
            // Emit each grapheme at its actual cell coordinate. SVG renderers
            // disagree about trailing spaces when textLength stretches a run.
            let mut column = x;
            while column < end {
                let symbol = buffer[(column, y)].symbol();
                let cells = unicode_width::UnicodeWidthStr::width(symbol).max(1) as u16;
                if !symbol.trim().is_empty() {
                    let px = 14.0 + column as f64 * 8.4;
                    let _ = writeln!(
                        output,
                        "<text x=\"{px:.1}\" y=\"{}\" fill=\"{}\"{weight} textLength=\"{:.1}\" lengthAdjust=\"spacingAndGlyphs\">{}</text>",
                        py + 14,
                        color(cell.fg),
                        cells as f64 * 8.4,
                        escape(symbol)
                    );
                }
                column += cells;
            }
            x = end;
        }
    }
    output.push_str("</g></svg>\n");
    output
}
fn shot(app: &App, output: &Path, name: &str, title: &str) -> Result<()> {
    let mut terminal = Terminal::new(TestBackend::new(128, 34))?;
    terminal.draw(|f| app.draw(f))?;
    let buffer = terminal.backend().buffer();
    let rendered = svg(buffer, title);
    for root in [app.root.clone(), app.root.canonicalize()?] {
        anyhow::ensure!(
            !rendered.contains(&escape(&root.display().to_string())),
            "截图包含本机项目路径"
        );
    }
    std::fs::write(output.join(name), rendered)?;
    if std::env::var_os("ZERO_SHOTS_TEXT").is_some() {
        let text = (0..buffer.area.height)
            .map(|y| {
                let mut line = String::new();
                let mut x = 0;
                while x < buffer.area.width {
                    let symbol = buffer[(x, y)].symbol();
                    line.push_str(symbol);
                    x += unicode_width::UnicodeWidthStr::width(symbol).max(1) as u16;
                }
                line
            })
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(output.join(name.replace(".svg", ".txt")), text)?;
    }
    Ok(())
}
pub fn run(image: &Path, symbols: &Path, output: &Path) -> Result<()> {
    let project = tempfile::tempdir()?;
    let root = project.path();
    std::fs::create_dir_all(root.join("images"))?;
    std::fs::create_dir_all(root.join("symbols"))?;
    let local_image = root
        .join("images")
        .join(image.file_name().context("镜像路径无效")?);
    let local_symbols = root
        .join("symbols")
        .join(symbols.file_name().context("符号路径无效")?);
    std::fs::copy(image, &local_image)?;
    std::fs::copy(symbols, &local_symbols)?;
    let cache = root.join(".zero/rust");
    let settings = Settings {
        remote_symbols: false,
        theme: "slate".into(),
        ..Default::default()
    };
    store::save_settings(&cache, &settings)?;
    let mut app = App::new(Some(local_image), local_symbols, cache, settings);
    app.initialize(Default::default());
    settle(&mut app)?;
    for plugin in [
        Plugin::Pslist,
        Plugin::Lsmod,
        Plugin::Sockstat,
        Plugin::Pstree,
    ] {
        app.activate_plugin(plugin);
        settle(&mut app)?;
        anyhow::ensure!(app.result().is_some(), "插件未产生结果: {}", plugin.name());
    }
    std::fs::create_dir_all(output)?;
    app.row = 2;
    app.focus = Focus::Content;
    shot(
        &app,
        output,
        "analysis.svg",
        "zero — pstree · Debian 3.2 sample",
    )?;
    app.activate_plugin(Plugin::Sockstat);
    settle(&mut app)?;
    shot(
        &app,
        output,
        "sockstat.svg",
        "zero — sockstat · process sockets",
    )?;
    app.activate_plugin(Plugin::Lsmod);
    settle(&mut app)?;
    app.settings.theme = "light".into();
    shot(&app, output, "theme-light.svg", "zero — lsmod · 纸白 theme")?;
    app.settings.theme = "slate".into();
    app.run_command(Command::KernelDiagnostics);
    settle(&mut app)?;
    anyhow::ensure!(
        app.kernel_report.as_ref().is_some_and(|r| r.passed() > 0),
        "内核诊断未通过"
    );
    shot(
        &app,
        output,
        "kernel-diagnostics.svg",
        "zero — kernel diagnostic report",
    )?;
    app.dialog = None;
    app.switch_page(Page::Assets);
    app.section = AssetSection::Images;
    shot(&app, output, "assets.svg", "zero — resource library")?;
    app.switch_page(Page::Cache);
    settle(&mut app)?;
    shot(&app, output, "cache.svg", "zero — cache management")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn svg_places_graphemes_without_stretching_padding() {
        let mut buffer = Buffer::empty(Rect::new(0, 0, 6, 1));
        buffer[(0, 0)].set_symbol("中");
        buffer[(2, 0)].set_symbol("A");
        let output = svg(&buffer, "test");
        assert!(output.contains("textLength=\"16.8\" lengthAdjust=\"spacingAndGlyphs\">中"));
        assert!(output.contains("<text x=\"30.8\" y=\"58\""));
        assert!(!output.contains("textLength=\"50.4\""));
    }
}
