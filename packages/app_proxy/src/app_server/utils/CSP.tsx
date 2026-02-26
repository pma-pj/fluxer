/*
 * Copyright (C) 2026 Fluxer Contributors
 *
 * This file is part of Fluxer.
 *
 * Fluxer is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Fluxer is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with Fluxer. If not, see <https://www.gnu.org/licenses/>.
 */

import {randomBytes} from 'node:crypto';
import {parseSentryDSN} from '@fluxer/app_proxy/src/app_server/utils/SentryDSN';

export interface CSPOptions {
	defaultSrc?: ReadonlyArray<string>;
	scriptSrc?: ReadonlyArray<string>;
	styleSrc?: ReadonlyArray<string>;
	imgSrc?: ReadonlyArray<string>;
	mediaSrc?: ReadonlyArray<string>;
	fontSrc?: ReadonlyArray<string>;
	connectSrc?: ReadonlyArray<string>;
	frameSrc?: ReadonlyArray<string>;
	workerSrc?: ReadonlyArray<string>;
	manifestSrc?: ReadonlyArray<string>;
	reportUri?: string;
}

export interface CSPConfig {
	sentryDsn: string;
	csp: {
		defaultSrc: string[];
		scriptSrc: string[];
		styleSrc: string[];
		imgSrc: string[];
		mediaSrc: string[];
		fontSrc: string[];
		connectSrc: string[];
		frameSrc: string[];
		workerSrc: string[];
		manifestSrc: string[];
		objectSrc: string[];
		baseUri: string;
		frameAncestors: string[];
	}
}

export function generateNonce(): string {
	return randomBytes(16).toString('hex');
}

export function buildSentryReportURI(config: CSPConfig): string {
	const sentry = parseSentryDSN(config.sentryDsn);
	if (!sentry) {
		return '';
	}

	let uri = `${sentry.targetUrl}${sentry.pathPrefix}/api/${sentry.projectId}/security/?sentry_version=7`;

	if (sentry.publicKey) {
		uri += `&sentry_key=${sentry.publicKey}`;
	}

	return uri;
}

export function buildCSP(nonce: string, options?: CSPOptions): string {
	const defaultSrc = ["'self'", ...(options?.defaultSrc ?? [])];
	const scriptSrc = ["'self'", `'nonce-${nonce}'`, "'wasm-unsafe-eval'", ...(options?.scriptSrc ?? [])];
	const styleSrc = ["'self'", "'unsafe-inline'", ...(options?.styleSrc ?? [])];
	const imgSrc = ["'self'", 'blob:', 'data:', ...(options?.imgSrc ?? [])];
	const mediaSrc = ["'self'", 'blob:', ...(options?.mediaSrc ?? [])];
	const fontSrc = ["'self'", 'data:', ...(options?.fontSrc ?? [])];
	const connectSrc = ["'self'", 'data:', ...(options?.connectSrc ?? [])];
	const frameSrc = ["'self'", ...(options?.frameSrc ?? [])];
	const workerSrc = ["'self'", 'blob:', ...(options?.workerSrc ?? [])];
	const manifestSrc = ["'self'", ...(options?.manifestSrc ?? [])];

	const directives = [
		`default-src ${defaultSrc.join(' ')}`,
		`script-src ${scriptSrc.join(' ')}`,
		`style-src ${styleSrc.join(' ')}`,
		`img-src ${imgSrc.join(' ')}`,
		`media-src ${mediaSrc.join(' ')}`,
		`font-src ${fontSrc.join(' ')}`,
		`connect-src ${connectSrc.join(' ')}`,
		`frame-src ${frameSrc.join(' ')}`,
		`worker-src ${workerSrc.join(' ')}`,
		`manifest-src ${manifestSrc.join(' ')}`,
		"object-src 'none'",
		"base-uri 'self'",
		"frame-ancestors 'none'",
	];

	if (options?.reportUri) {
		directives.push(`report-uri ${options.reportUri}`);
	}

	return directives.join('; ');
}

export function buildFluxerCSPOptions(config: CSPConfig): CSPOptions {
	const reportURI = buildSentryReportURI(config);
	const sentry = parseSentryDSN(config.sentryDsn);
	const connectSrc: Array<string> = [...config.csp.connectSrc];
	if (sentry) {
		connectSrc.push(sentry.targetUrl);
	}

	return {
		scriptSrc: [...config.csp.scriptSrc],
		styleSrc: [...config.csp.styleSrc],
		imgSrc: [...config.csp.imgSrc],
		mediaSrc: [...config.csp.mediaSrc],
		fontSrc: [...config.csp.fontSrc],
		connectSrc: Array.from(new Set(connectSrc)),
		frameSrc: [...config.csp.frameSrc],
		workerSrc: [...config.csp.workerSrc],
		manifestSrc: [...config.csp.manifestSrc],
		reportUri: reportURI || undefined,
	};
}

export function buildFluxerCSP(nonce: string, config: CSPConfig): string {
	return buildCSP(nonce, buildFluxerCSPOptions(config));
}
