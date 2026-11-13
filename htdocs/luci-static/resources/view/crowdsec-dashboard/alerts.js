// SPDX-License-Identifier: Apache-2.0
'use strict';
'require view';
'require dom';
'require rpc';
'require poll';

const callAlerts = rpc.declare({ object: 'luci.crowdsec', method: 'alerts', params: [ 'limit' ], expect: { alerts: [] } });

function fmtTime(t) {
	return t ? t.replace('T', ' ').replace(/(\.\d+)?Z$/, ' UTC') : '-';
}

function count(list, key) {
	const m = {};
	list.forEach(a => { const k = a[key] || '-'; m[k] = (m[k] || 0) + 1; });
	return Object.keys(m).sort((a, b) => m[b] - m[a]).slice(0, 10).map(k => [ k, m[k] ]);
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

function renderAll(alerts, filter) {
	const f = (filter || '').toLowerCase();
	const list = f ? alerts.filter(a => [ a.scenario, a.ip, a.country, a.as_name, a.message ].join(' ').toLowerCase().indexOf(f) >= 0) : alerts;

	return E('div', [
		E('div', { 'style': 'display:flex;gap:2em;flex-wrap:wrap' }, [
			E('div', { 'style': 'flex:1;min-width:280px' }, [ E('h4', [ _('Top scenarios') ]), table([ _('Scenario'), _('Alerts') ], count(list, 'scenario'), _('None')) ]),
			E('div', { 'style': 'flex:1;min-width:280px' }, [ E('h4', [ _('Top sources') ]), table([ _('Source'), _('Alerts') ], count(list, 'ip'), _('None')) ])
		]),
		E('h4', [ _('Recent alerts (%d)').format(list.length) ]),
		table([ _('Time'), _('Scenario'), _('Source'), _('Country / AS'), _('Events'), _('Decision') ],
			list.map(a => [
				fmtTime(a.created_at), a.scenario || '-', a.ip || '-',
				[ a.country, a.as_name ].filter(x => x).join(' / ') || '-',
				String(a.events || 0), a.decision || _('none')
			]),
			_('No alerts. CrowdSec raises an alert when a scenario (for example SSH brute force) triggers on the logs it reads.'))
	]);
}

return view.extend({
	load: function() {
		return callAlerts(200);
	},

	render: function(alerts) {
		let current = alerts || [];
		const out = E('div', { 'id': 'cs-alerts' }, [ renderAll(current, '') ]);
		const filter = E('input', {
			'class': 'cbi-input-text', 'type': 'text', 'placeholder': _('Filter by scenario, IP, country…'),
			'input': ev => dom.content(out, renderAll(current, ev.target.value))
		});

		poll.add(() => callAlerts(200).then(a => {
			current = a || [];
			dom.content(out, renderAll(current, filter.value));
		}), 30);

		return E('div', { 'class': 'cbi-map' }, [
			E('h2', [ _('CrowdSec: Alerts') ]),
			E('div', { 'class': 'cbi-map-descr' }, [ _('Detections made by this engine from its own logs (the last 200). Community blocklist entries are not alerts; see Decisions.') ]),
			E('div', { 'class': 'cbi-section' }, [ filter, out ])
		]);
	},

	handleSaveApply: null,
	handleSave: null,
	handleReset: null
});
