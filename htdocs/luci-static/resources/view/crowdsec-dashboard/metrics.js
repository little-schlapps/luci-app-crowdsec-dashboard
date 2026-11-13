// SPDX-License-Identifier: Apache-2.0
'use strict';
'require view';
'require dom';
'require rpc';
'require poll';

const callMetrics = rpc.declare({ object: 'luci.crowdsec', method: 'metrics', expect: { } });

function n(v) {
	return String(v || 0).replace(/\B(?=(\d{3})+(?!\d))/g, ' ');
}

function table(headers, rows, empty) {
	const t = E('table', { 'class': 'table' }, [
		E('tr', { 'class': 'tr table-titles' }, headers.map(h => E('th', { 'class': 'th left' }, [ h ])))
	]);

	if (!rows.length)
		t.appendChild(E('tr', { 'class': 'tr placeholder' }, [ E('td', { 'class': 'td', 'colspan': headers.length }, [ E('em', [ empty ]) ]) ]));

	rows.forEach(r => t.appendChild(E('tr', { 'class': 'tr' }, r.map(c => E('td', { 'class': 'td left' }, [ c ])))));
	return t;
}

function objRows(obj, cols) {
	return Object.keys(obj || {}).sort().map(k => [ k ].concat(cols.map(c => n(obj[k][c]))));
}

function whitelistRows(wl) {
	const rows = [];

	Object.keys(wl || {}).sort().forEach(name =>
		Object.keys(wl[name] || {}).sort().forEach(reason =>
			rows.push([ name, reason, n(wl[name][reason].hits), n(wl[name][reason].whitelisted) ])));

	return rows;
}

function renderAll(m) {
	return E('div', [
		E('div', { 'class': 'cbi-section' }, [
			E('h3', [ _('Log sources') ]),
			table([ _('Source'), _('Lines read'), _('Parsed'), _('Unparsed'), _('Poured to bucket') ],
				objRows(m.acquisition, [ 'reads', 'parsed', 'unparsed', 'pour' ]), _('No log sources reporting'))
		]),
		E('div', { 'class': 'cbi-section' }, [
			E('h3', [ _('Parsers') ]),
			table([ _('Parser'), _('Hits'), _('Parsed'), _('Unparsed') ],
				objRows(m.parsers, [ 'hits', 'parsed', 'unparsed' ]), _('No parser activity'))
		]),
		E('div', { 'class': 'cbi-section' }, [
			E('h3', [ _('Scenarios') ]),
			table([ _('Scenario'), _('Current'), _('Overflows'), _('Instantiated'), _('Poured'), _('Expired') ],
				objRows(m.scenarios, [ 'curr_count', 'overflow', 'instantiation', 'pour', 'underflow' ]), _('No scenario activity yet'))
		]),
		E('div', { 'class': 'cbi-section' }, [
			E('h3', [ _('Whitelists') ]),
			table([ _('Whitelist'), _('Reason'), _('Hits'), _('Whitelisted') ],
				whitelistRows(m.whitelists), _('Nothing whitelisted yet'))
		]),
		E('div', { 'class': 'cbi-section' }, [
			E('h3', [ _('Installed collections') ]),
			table([ _('Collection'), _('Version'), _('Status') ],
				(m.collections || []).map(c => [ c.name, c.version || '-', c.status || '-' ]), _('No collections installed'))
		])
	]);
}

return view.extend({
	load: function() {
		return callMetrics();
	},

	render: function(m) {
		const out = E('div', [ renderAll(m || {}) ]);

		poll.add(() => callMetrics().then(m => dom.content(out, renderAll(m || {}))), 30);

		return E('div', { 'class': 'cbi-map' }, [
			E('h2', [ _('CrowdSec: Metrics') ]),
			E('div', { 'class': 'cbi-map-descr' }, [ _('What the engine reads and how it is processed (counters since the engine last started). Lines that no parser recognises are normal for logs CrowdSec has no collection for.') ]),
			out
		]);
	},

	handleSaveApply: null,
	handleSave: null,
	handleReset: null
});
