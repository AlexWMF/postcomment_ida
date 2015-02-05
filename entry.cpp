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

static void idaapi run(int)
{
	ea_t ea = get_screen_ea();
	if (ea == BADADDR)
		return;

	flags_t flags = getFlags(ea);
	if (!isCode(flags))
		return;

	func_t* const f = get_func(ea);
	if (!f)
		return;

	func_item_iterator_t it;
	if (!it.set(f))
		return;

	char mnem[MAXSTR] = {};
	qvector<ea_t> funcItems;
	do
	{
		ea_t e = it.current();
		if (e == BADADDR || e < ea)
			continue;
		funcItems.push_back(e);
	} while (it.next_code());

	const size_t len = funcItems.size();
	size_t cnt = 0;
	for (size_t i = 0; i < len; ++i)
	{
		const ea_t e = funcItems[i];
		mnem[0] = '\0';
		if (!ua_mnem(e, mnem, MAXSTR))
			return;
		if (StrCmpIA(mnem, "call") != 0)
			continue;
		if (i < len - 1)
		{
			const ea_t cRef = get_first_fcref_to(funcItems[i+1]);
			if (cRef != BADADDR)  // check is there also space after provided by label of xref
				continue;
		}

		update_extra_cmt(e, E_NEXT, " ");
		setFlbits(e, 0x00002000LU); // FL_LINE, FIXME: limitation by IDA API
		cnt++;
	}
	msg("POSTCOMM: Added %u posteriors\n", cnt);
}

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