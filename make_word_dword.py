############################################################################################
##
## IDA Pro Plugin: Quick Make Word and Double Word
##
## Provide actions and shortcuts to create Word and Double Word in IDA view and Struct view.
##
## Available for IDA 7+. Tested on IDA 8.3.
##
## To install:
##      Copy script into plugins directory, i.e: C:\Program Files\<ida version>\plugins
##
## To use:
##      In IDA View or Struct View, right-click an address and type 'Make Word' or 'Make Double Word',
##      or use the hotkeys 'W' and 'Shift+D' respectively.
##
############################################################################################

__AUTHOR__ = "@sean2077"

PLUGIN_NAME = "Quick Make Word and Double Word"
PLUGIN_MAKE_WORD_HOTKEY = "W"
PLUGIN_MAKE_DWORD_HOTKEY = "Shift+D"
VERSION = "1.0.0"

import ida_kernwin
import ida_moves
import ida_struct
import idaapi
import idc

ACTION_PREFIX = "sean2077"


def make_word_action():
    form_type = idaapi.get_widget_type(idaapi.get_current_widget())

    if form_type == idaapi.BWN_DISASM:

        ea = idc.get_screen_ea()
        if ea == idaapi.BADADDR:
            idaapi.warning("Invalid address selected")
            return

        idc.create_word(ea)
        idaapi.msg(f"Created word at {ea:#X}\n")

    elif form_type == idaapi.BWN_STRUCTS:

        view = idaapi.get_current_viewer()
        loc = ida_moves.lochist_entry_t()
        if not ida_kernwin.get_custom_viewer_location(loc, view):
            idaapi.warning("Failed to get location")
            return

        place = loc.place()
        structplace = ida_kernwin.place_t_as_structplace_t(place)

        struc = ida_struct.get_struc_by_idx(structplace.idx)
        if struc == idaapi.BADADDR:
            idaapi.warning("Invalid structure selected")
            return

        sptr = ida_struct.get_struc(struc)

        field_name = f"field_{structplace.offset:X}"
        ida_struct.add_struc_member(sptr, field_name, structplace.offset, idc.FF_WORD, None, 2)

        idaapi.msg(
            f"Created word field: {field_name} at offset {structplace.offset:#X} in structure {ida_struct.get_struc_name(struc)}\n"
        )

    else:
        idaapi.warning("Invalid view selected")


def make_double_word_action():
    form_type = idaapi.get_widget_type(idaapi.get_current_widget())

    if form_type == idaapi.BWN_DISASM:

        ea = idc.get_screen_ea()
        if ea == idaapi.BADADDR:
            idaapi.warning("Invalid address selected")
            return

        idc.create_dword(ea)
        idaapi.msg(f"Created double word at {ea:#X}\n")

    elif form_type == idaapi.BWN_STRUCTS:

        view = idaapi.get_current_viewer()
        loc = ida_moves.lochist_entry_t()
        if not ida_kernwin.get_custom_viewer_location(loc, view):
            idaapi.warning("Failed to get location")
            return

        place = loc.place()
        structplace = ida_kernwin.place_t_as_structplace_t(place)

        struc = ida_struct.get_struc_by_idx(structplace.idx)
        if struc == idaapi.BADADDR:
            idaapi.warning("Invalid structure selected")
            return

        sptr = ida_struct.get_struc(struc)

        field_name = f"field_{structplace.offset:X}"
        ida_struct.add_struc_member(sptr, field_name, structplace.offset, idc.FF_DWORD, None, 4)

        idaapi.msg(
            f"Created double word field: {field_name} at offset {structplace.offset:#X} in structure {ida_struct.get_struc_name(struc)}\n"
        )

    else:
        idaapi.warning("Invalid view selected")


class QuickMakePlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_PROC | idaapi.PLUGIN_HIDE
    comment = "Quick Make Word and Double Word"
    help = "Right-click an address and select 'Make Word' or 'Make Double Word'"
    wanted_name = PLUGIN_NAME

    def init(self):
        self._init_action_make_word()
        self._init_action_make_double_word()
        self._init_hooks()
        idaapi.msg("%s %s initialized...\n" % (self.wanted_name, VERSION))
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        idaapi.msg("%s cannot be run as a script.\n" % self.wanted_name)

    def term(self):
        self._hooks.unhook()
        self._del_action_make_word()
        self._del_action_make_double_word()
        idaapi.msg("%s terminated...\n" % self.wanted_name)

    def _init_hooks(self):
        self._hooks = Hooks()
        self._hooks.hook()

    ACTION_MAKE_WORD = f"{ACTION_PREFIX}:make_word"
    ACTION_MAKE_DOUBLE_WORD = f"{ACTION_PREFIX}:make_double_word"

    def _init_action_make_word(self):
        action_desc = idaapi.action_desc_t(
            self.ACTION_MAKE_WORD,
            "Make Word",
            IDACtxEntry(make_word_action),
            PLUGIN_MAKE_WORD_HOTKEY,
            "Create a word at the current address",
            0,
        )
        assert idaapi.register_action(action_desc), "Action registration failed"

    def _init_action_make_double_word(self):
        action_desc = idaapi.action_desc_t(
            self.ACTION_MAKE_DOUBLE_WORD,
            "Make Double Word",
            IDACtxEntry(make_double_word_action),
            PLUGIN_MAKE_DWORD_HOTKEY,
            "Create a double word at the current address",
            0,
        )
        assert idaapi.register_action(action_desc), "Action registration failed"

    def _del_action_make_word(self):
        idaapi.unregister_action(self.ACTION_MAKE_WORD)

    def _del_action_make_double_word(self):
        idaapi.unregister_action(self.ACTION_MAKE_DOUBLE_WORD)


class Hooks(idaapi.UI_Hooks):
    def finish_populating_widget_popup(self, widget, popup):
        form_type = idaapi.get_widget_type(widget)
        inject_quickmake_actions(widget, popup, form_type)
        return 0


def inject_quickmake_actions(widget, popup, form_type):
    if form_type in (idaapi.BWN_DISASM, form_type == idaapi.BWN_STRUCTS):
        idaapi.attach_action_to_popup(widget, popup, QuickMakePlugin.ACTION_MAKE_WORD, "Make Word", idaapi.SETMENU_APP)
        idaapi.attach_action_to_popup(
            widget, popup, QuickMakePlugin.ACTION_MAKE_DOUBLE_WORD, "Make Double Word", idaapi.SETMENU_APP
        )

    return 0


class IDACtxEntry(idaapi.action_handler_t):
    def __init__(self, action_function):
        idaapi.action_handler_t.__init__(self)
        self.action_function = action_function

    def activate(self, ctx):
        self.action_function()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


def PLUGIN_ENTRY():
    return QuickMakePlugin()
