// SPDX-License-Identifier: Apache-2.0
'use strict';
'require view';
'require dom';
'require rpc';
'require ui';

const callDecisions = rpc.declare({ object: 'luci.crowdsec', method: 'decisions', expect: { decisions: [] } });
const callLookup = rpc.declare({ object: 'luci.crowdsec', method: 'lookup', params: [ 'ip' ], expect: { } });
const callUnblock = rpc.declare({ object: 'luci.crowdsec', method: 'unblock', params: [ 'ip' ], expect: { } });
const callBan = rpc.declare({ object: 'luci.crowdsec', method: 'ban', params: [ 'ip', 'duration' ], expect: { } });

const IP_RE = /^[0-9A-Fa-f:.]+(\/[0-9]{1,3})?$/;

function table(headers, rows, empty) {
	const t = E('table', { 'class': 'table' }, [
		E('tr', { 'class': 'tr table-titles' }, headers.map(h => E('th', { 'class': 'th left' }, [ h ])))
	]);

	if (!rows.length)
		t.appendChild(E('tr', { 'class': 'tr placeholder' }, [ E('td', { 'class': 'td', 'colspan': headers.length }, [ E('em', [ empty ]) ]) ]));

	rows.forEach(r => t.appendChild(E('tr', { 'class': 'tr' }, r.map(c => E('td', { 'class': 'td left' }, [ c ])))));
	return t;
}

// Go duration "111h37m1.787s" -> "4d 15h 37m"
function fmtDuration(s) {
	const m = String(s || '').match(/^(?:(\d+)h)?(?:(\d+)m)?(?:[\d.]+s)?$/);
	if (!s || !m)
		return s || '-';

	const h = +(m[1] || 0), min = +(m[2] || 0);
	const d = Math.floor(h / 24);

	if (d)
		return '%dd %dh %dm'.format(d, h % 24, min);

	return h ? '%dh %dm'.format(h, min) : (min ? '%dm'.format(min) : _('< 1m'));
}

function decisionRows(list, withButton, refresh) {
	return list.map(d => {
		const cells = [ d.value || '-', d.type || '-', d.origin || '-', d.scenario || '-', fmtDuration(d.duration), [ d.country, d.as_name ].filter(x => x).join(' / ') || '-' ];

		if (withButton)
			cells.push(E('button', {
				'class': 'btn cbi-button cbi-button-remove',
				'click': ui.createHandlerFn(this, () => unblock(d.value, refresh))
			}, [ _('Unblock') ]));

		return cells;
	});
}

function notify(res, okText) {
	if (!res || !res.result)
		ui.addNotification(null, E('p', [ _('Failed: %s').format(res && res.error || '?') ]), 'danger');
	else
		ui.addNotification(null, E('p', [ okText, res.output ? ' (' + res.output + ')' : '' ]), 'info');
}

function unblock(ip, refresh) {
	return callUnblock(ip).then(r => { notify(r, _('Removed decisions for %s').format(ip)); return refresh(); });
}

return view.extend({
	load: function() {
		return callDecisions();
	},

	render: function(decisions) {
		const local = E('div');
		const lookupOut = E('div');

		const refresh = () => callDecisions().then(d => dom.content(local, table(
			[ _('IP / range'), _('Action'), _('Origin'), _('Reason'), _('Expires in'), _('Country / AS'), '' ],
			decisionRows(d || [], true, refresh),
			_('No local decisions. The community blocklist is not listed here; use the lookup below to check an address.'))));

		dom.content(local, table(
			[ _('IP / range'), _('Action'), _('Origin'), _('Reason'), _('Expires in'), _('Country / AS'), '' ],
			decisionRows(decisions || [], true, refresh),
			_('No local decisions. The community blocklist is not listed here; use the lookup below to check an address.')));

		const ipIn = E('input', { 'class': 'cbi-input-text', 'type': 'text', 'placeholder': '203.0.113.7' });
		const dur = E('select', { 'class': 'cbi-input-select' }, [
			E('option', { 'value': '1h' }, [ _('1 hour') ]),
			E('option', { 'value': '4h', 'selected': 'selected' }, [ _('4 hours') ]),
			E('option', { 'value': '24h' }, [ _('24 hours') ]),
			E('option', { 'value': '168h' }, [ _('7 days') ])
		]);

		const getIp = () => {
			const ip = ipIn.value.trim();
			if (!IP_RE.test(ip)) {
				ui.addNotification(null, E('p', [ _('Enter an IPv4/IPv6 address or range') ]), 'warning');
				return null;
			}
			return ip;
		};

		const doLookup = () => {
			const ip = getIp();
			if (!ip)
				return Promise.resolve();

			return callLookup(ip).then(r => dom.content(lookupOut, r.error ? E('em', [ r.error ]) :
				(r.decisions || []).length
					? table([ _('IP / range'), _('Action'), _('Origin'), _('Reason'), _('Expires in'), _('Country / AS') ], decisionRows(r.decisions, false), '')
					: E('p', [ E('span', { 'class': 'label success' }, [ _('Not blocked') ]), ' ', _('%s has no active decision (local or community).').format(ip) ])));
		};

		const doBan = () => {
			const ip = getIp();
			if (!ip)
				return Promise.resolve();

			return callBan(ip, dur.value).then(r => { notify(r, _('Banned %s for %s').format(ip, dur.value)); return refresh(); });
		};

		const doUnblock = () => {
			const ip = getIp();
			return ip ? unblock(ip, refresh).then(doLookup) : Promise.resolve();
		};

		return E('div', { 'class': 'cbi-map' }, [
			E('h2', [ _('CrowdSec: Decisions') ]),
			E('div', { 'class': 'cbi-map-descr' }, [ _('Local decisions are bans made by this engine or by hand. The community blocklist (CAPI) can hold thousands of addresses and is only searched by lookup.') ]),
			E('div', { 'class': 'cbi-section' }, [ E('h3', [ _('Local decisions') ]), local ]),
			E('div', { 'class': 'cbi-section' }, [
				E('h3', [ _('Look up, ban or unblock an address') ]),
				E('div', { 'style': 'display:flex;gap:.5em;flex-wrap:wrap;align-items:center' }, [
					ipIn,
					E('button', { 'class': 'btn cbi-button cbi-button-action', 'click': ui.createHandlerFn(this, doLookup) }, [ _('Look up') ]),
					dur,
					E('button', { 'class': 'btn cbi-button cbi-button-negative', 'click': ui.createHandlerFn(this, doBan) }, [ _('Ban') ]),
					E('button', { 'class': 'btn cbi-button cbi-button-remove', 'click': ui.createHandlerFn(this, doUnblock) }, [ _('Unblock') ])
				]),
				lookupOut
			])
		]);
	},

	handleSaveApply: null,
	handleSave: null,
	handleReset: null
});
