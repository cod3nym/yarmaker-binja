"""YarMaker - create YARA signatures from selection (Binary Ninja plugin)"""

# Binary Ninja imports the plugin folder as a package; skip registration when
# this file is imported standalone (e.g. by test runners)
if __package__:
    from .yarmaker.plugin import register

    register()
