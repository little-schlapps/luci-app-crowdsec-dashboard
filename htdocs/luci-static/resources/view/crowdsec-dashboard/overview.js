// SPDX-License-Identifier: Apache-2.0
'use strict';
'require view';
'require dom';
'require rpc';
'require poll';

const callStatus = rpc.declare({ object: 'luci.crowdsec', method: 'status', expect: { } });
const callCapi = rpc.declare({ object: 'luci.crowdsec', method: 'capi_check', expect: { } });
const callBlocked = rpc.declare({ object: 'luci.crowdsec', method: 'blocked_log', params: [ 'lines' ], expect: { } });

function badge(ok, yes, no) {
	return E('span', { 'class': ok ? 'label success' : 'label warning' }, [ ok ? yes : no ]);
}

function row(label, value) {
	return E('tr', { 'class': 'tr' }, [
		E('td', { 'class': 'td left', 'width': '33%' }, [ label ]),
		E('td', { 'class': 'td left' }, [ value ])
	]);
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

function fmtCount(n) {
	return String(n || 0).replace(/\B(?=(\d{3})+(?!\d))/g, ' ');
}

function renderStatus(st) {
	const bouncers = (st.bouncers || []).map(b => '%s (%s)'.format(b.name, b.revoked ? _('revoked') : (b.last_pull ? _('last pull %s').format(b.last_pull.replace('T', ' ').replace(/\..*$/, '')) : _('never pulled'))));

	return E('table', { 'class': 'table' }, [
		row(_('Security engine'), badge(st.engine, _('Running'), _('Not running'))),
		row(_('Firewall bouncer'), badge(st.bouncer, _('Running'), _('Not running'))),
		row(_('Version'), st.version || '-'),
		row(_('Registered bouncers'), bouncers.length ? bouncers.join(', ') : '-'),
		row(_('Blocked IP addresses'), E('strong', [ fmtCount(st.decisions_total) ])),
		row(_('Central API (community blocklist)'), E('span', { 'id': 'cs-capi' }, [
			st.capi_credentials ? E('em', [ _('checking…') ]) : badge(false, '', _('Not registered'))
		]))
	]);
}

function renderDecisions(st) {
	return table([ _('Reason'), _('Origin'), _('Action'), _('IPs') ],
		(st.decisions || []).map(d => [ d.reason, d.origin, d.action, fmtCount(d.count) ]),
		_('No active decisions'));
}

function renderCounters(st) {
	const c = st.counters || {};
	const rows = Object.keys(c).sort().map(k => {
		const name = k.replace(/^ip6?:/, '');
		const fam = k.indexOf('ip6:') === 0 ? 'IPv6' : 'IPv4';
		const label = name === 'processed' ? _('Packets checked') : _('Dropped by %s').format(name.replace(/^crowdsec6?-blacklists-?/, '') || _('local decisions'));
		return [ '%s (%s)'.format(label, fam), fmtCount(c[k].packets), '%1024.2mB'.format(c[k].bytes || 0) ];
	});

	return table([ _('Counter'), _('Packets'), _('Bytes') ], rows, _('No firewall counters found (bouncer not running?)'));
}

function renderBlocked(bl) {
	const top = table([ _('Source'), _('Dropped packets logged') ],
		(bl.top || []).slice(0, 10).map(t => [ t.ip, fmtCount(t.count) ]),
		_('No dropped packets in the system log'));

	const recent = table([ _('Time'), _('In'), _('Source'), _('Destination'), _('Proto/port') ],
		(bl.recent || []).slice(0, 20).map(e => [ e.time, e.in || '-', e.src || '-', e.dst || '-', '%s %s'.format(e.proto || '', e.dpt || '') ]),
		_('No dropped packets in the system log'));

	return E('div', [ E('h4', [ _('Top blocked sources') ]), top, E('h4', [ _('Most recent drops') ]), recent ]);
}

return view.extend({
	load: function() {
		return Promise.all([ callStatus(), callBlocked(500) ]);
	},

	render: function(data) {
		const st = data[0] || {}, bl = data[1] || {};

		const view = E('div', { 'class': 'cbi-map' }, [
			E('h2', [ _('CrowdSec') ]),
			E('div', { 'class': 'cbi-map-descr' }, [
				_('Engine health, blocklists and firewall drops. Settings for the firewall bouncer are under Network → Firewall → CrowdSec Bouncer.')
			]),
			E('div', { 'class': 'cbi-section' }, [ E('h3', [ _('Status') ]), E('div', { 'id': 'cs-status' }, [ renderStatus(st) ]) ]),
			E('div', { 'class': 'cbi-section' }, [ E('h3', [ _('Active decisions by reason') ]), E('div', { 'id': 'cs-decisions' }, [ renderDecisions(st) ]) ]),
			E('div', { 'class': 'cbi-section' }, [
				E('h3', [ _('Firewall counters') ]),
				E('div', { 'class': 'cbi-section-descr' }, [
					_('The bouncer checks new connections arriving on its interfaces after the main firewall. Traffic the firewall already drops (any unsolicited inbound connection when no port is open) never reaches it, so zeros here are normal on a router with no open WAN ports.')
				]),
				E('div', { 'id': 'cs-counters' }, [ renderCounters(st) ])
			]),
			E('div', { 'class': 'cbi-section' }, [
				E('h3', [ _('Dropped traffic (system log, last 500 entries)') ]),
				E('div', { 'id': 'cs-blocked' }, [ renderBlocked(bl) ])
			])
		]);

		if (st.capi_credentials)
			callCapi().then(r => {
				const el = document.getElementById('cs-capi');
				if (el)
					dom.content(el, badge(r && r.ok, _('Connected'), _('Unreachable')));
			});

		poll.add(() => Promise.all([ callStatus(), callBlocked(500) ]).then(d => {
			const st = d[0] || {}, bl = d[1] || {};
			const capi = document.getElementById('cs-capi');
			const keep = capi ? capi.firstChild : null;

			dom.content(document.getElementById('cs-status'), renderStatus(st));
			if (keep)
				dom.content(document.getElementById('cs-capi'), keep);
			dom.content(document.getElementById('cs-decisions'), renderDecisions(st));
			dom.content(document.getElementById('cs-counters'), renderCounters(st));
			dom.content(document.getElementById('cs-blocked'), renderBlocked(bl));
		}), 30);

		return view;
	},

	handleSaveApply: null,
	handleSave: null,
	handleReset: null
});
