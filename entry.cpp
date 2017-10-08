#include <windows.h>

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <bytes.hpp>
#include <Shlwapi.h>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	return TRUE;
}

void addPosteriorCommentsToSelectedFunc()
{
	ea_t ea = get_screen_ea();
	if (ea == BADADDR)
		return;

#if (IDA_SDK_VERSION < 700)
	flags_t flags = getFlags(ea);
	if (!isCode(flags))
		return;
#else // IDA_SDK_VERSION < 700
	flags_t flags = get_flags(ea);
	if (!is_code(flags))
		return;
#endif // IDA_SDK_VERSION < 700
	func_t* const f = get_func(ea);
	if (!f)
		return;

	func_item_iterator_t it;
	if (!it.set(f))
		return;

	qstring qmnem;
#if (IDA_SDK_VERSION < 700)
	char mnem[MAXSTR] = {};
#endif // IDA_SDK_VERSION < 700
	qvector<ea_t> funcItems;
	do
	{
		ea_t e = it.current();
		if (e == BADADDR)
			continue;
		funcItems.push_back(e);
	} while (it.next_code());

	const size_t len = funcItems.size();
	size_t cnt = 0;
	for (size_t i = 0; i < len; ++i)
	{
		const ea_t e = funcItems[i];
#if (IDA_SDK_VERSION < 700)
		mnem[0] = '\0';
		if (!ua_mnem(e, mnem, MAXSTR))
			return;
#else // IDA_SDK_VERSION < 700
		if (!print_insn_mnem(&qmnem, e))
			return;
#endif // IDA_SDK_VERSION < 700

		if (StrCmpIA(qmnem.c_str(), "call") != 0)
			continue;
		if (i < len - 1)
		{
			const ea_t cRef = get_first_fcref_to(funcItems[i + 1]);
			if (cRef != BADADDR)  // check is there also space after provided by label of xref
				continue;
		}

		update_extra_cmt(e, E_NEXT, " ");
#if (IDA_SDK_VERSION < 700)
		setFlbits(e, 0x00002000LU); // FL_LINE, FIXME: limitation by IDA API
#endif // IDA_SDK_VERSION < 700
		cnt++;
	}

	qstring qfuncName;
#if (IDA_SDK_VERSION < 700)
	char funcName[MAXSTR] = {};
	get_func_name(ea, funcName, MAXSTR);
	qfuncName = funcName;
#else // IDA_SDK_VERSION < 700
	get_func_name(&qfuncName, ea);
#endif // IDA_SDK_VERSION < 700
	msg("POSTCOMM: Added %u posteriors to func:%s\n", cnt, qfuncName.c_str());
}


#if (IDA_SDK_VERSION < 700)
static void idaapi run(int)
{
	addPosteriorCommentsToSelectedFunc();
}
#else
static bool idaapi run(std::size_t)
{
	addPosteriorCommentsToSelectedFunc();
	return true;
}
#endif


static int idaapi init()
{
	if (ph.id != PLFM_386)
		return PLUGIN_SKIP;
	return PLUGIN_KEEP;
}

void idaapi term()
{
}

plugin_t PLUGIN =
{
	IDP_INTERFACE_VERSION,
	0,
	init,                 // initialize
	term,                 // terminate. this pointer may be NULL.
	run,                  // invoke plugin
	NULL,                 // long comment about the plugin
	NULL,                 // multiline help about the plugin
	"AlexWMF | Add posterior comments to all calls in this function",// the preferred short name of the plugin
	"F3"                  // the preferred hotkey to run the plugin
};