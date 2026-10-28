from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements

class ProcessorProbe(interfaces.plugins.PluginInterface):
    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)
    @classmethod
    def get_requirements(cls):
        return [requirements.ModuleRequirement(name="kernel", description="Exact kernel", architectures=["Intel32", "Intel64"])]
    def run(self):
        k = self.context.modules[self.config["kernel"]]
        off = k.get_symbol("KeNumberProcessors").address
        kpcr = k.get_type("_KPCR")
        row = (int(k.object("UChar", offset=off)), int(k.object("unsigned int", offset=off)), kpcr.relative_child_offset("Prcb"), kpcr.relative_child_offset("PrcbData"), kpcr.relative_child_offset("SelfPcr"))
        return renderers.TreeGrid([("Byte count", int), ("Reference uint count", int), ("Prcb offset", int), ("PrcbData offset", int), ("SelfPcr offset", int)], iter([(0, row)]))
