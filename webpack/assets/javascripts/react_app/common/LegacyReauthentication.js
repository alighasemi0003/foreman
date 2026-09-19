/* eslint-disable camelcase */
/**
 * Legacy HTML / Rails UJS adapter for step-up reauthentication.
 *
 * Backend remains source of truth: only opens the modal when the response
 * includes error.reauthentication_required. Does not decide which actions
 * are sensitive.
 */
import { translate as __ } from './I18n';
import { notify } from '../../foreman_toast_notifications';
import store from '../redux';
import { openConfirmModal } from '../components/ConfirmModal';
import {
  promptReauthentication,
  isReauthenticationRequiredPayload,
  reauthenticationActionFromPayload,
  reauthenticationSupportedFromPayload,
} from './Reauthentication';

const REAUTH_HEADER = 'X-Foreman-Accept-Reauth';
const MAX_REAUTH_RETRIES = 1;
const HANDLED_ATTR = 'data-foreman-reauth-handled';

let installed = false;

const csrfToken = () =>
  document.querySelector('meta[name="csrf-token"]')?.content || '';

const csrfParam = () =>
  document.querySelector('meta[name="csrf-param"]')?.content ||
  'authenticity_token';

const isRedirectStatus = status => status >= 300 && status < 400;

const navigateTo = url => {
  window.location.href = url;
};

const replaceDocumentWithHtml = async response => {
  const html = await response.text();
  document.open();
  document.write(html);
  document.close();
};

const parseJsonSafe = async response => {
  const contentType = response.headers.get('content-type') || '';
  if (!contentType.includes('application/json')) return null;
  try {
    return await response.json();
  } catch (e) {
    return null;
  }
};

/**
 * Application-styled confirmation (PatternFly) — never window.confirm.
 */
export const promptApplicationConfirm = ({
  title,
  message,
  isWarning = false,
  confirmButtonText = null,
} = {}) =>
  new Promise((resolve, reject) => {
    store.dispatch(
      openConfirmModal({
        title: title || __('Confirm'),
        message: message || '',
        isWarning,
        confirmButtonText,
        onConfirm: () => resolve(true),
        onCancel: () => reject(new Error('confirm_cancelled')),
      })
    );
  });

/**
 * Perform a legacy request; on reauth_required prompt once and retry once.
 * buildRequest must return a fresh { url, options } each call (no stored secrets).
 */
export const submitLegacyWithReauth = async (
  buildRequest,
  attempt = 0,
  reauthOpts = {}
) => {
  const { url, options } = buildRequest();
  const headers = new Headers(options.headers || {});
  headers.set(REAUTH_HEADER, '1');
  headers.set('X-Requested-With', 'XMLHttpRequest');
  if (csrfToken()) {
    headers.set('X-CSRF-Token', csrfToken());
  }
  if (!headers.has('Accept')) {
    headers.set(
      'Accept',
      'application/json, text/javascript, text/html, */*;q=0.01'
    );
  }

  const response = await fetch(url, {
    ...options,
    headers,
    credentials: 'same-origin',
    redirect: 'manual',
  });

  // Same-origin redirect (Rails process_success)
  if (
    response.type === 'opaqueredirect' ||
    isRedirectStatus(response.status)
  ) {
    const location = response.headers.get('Location');
    if (location) {
      navigateTo(location);
      return { status: 'redirected', location };
    }
    window.location.reload();
    return { status: 'reloaded' };
  }

  if (response.status === 403) {
    const data = await parseJsonSafe(response);
    if (
      isReauthenticationRequiredPayload(data) &&
      attempt < MAX_REAUTH_RETRIES
    ) {
      await promptReauthentication({
        action: reauthenticationActionFromPayload(data),
        unsupported: !reauthenticationSupportedFromPayload(data),
        contextMessage: reauthOpts.contextMessage,
      });
      return submitLegacyWithReauth(buildRequest, attempt + 1, reauthOpts);
    }

    // Authorization 403 or second reauth_required — do not open modal / loop
    const message =
      data?.error?.message ||
      __('You are not authorized to perform this action.');
    notify({ message, type: 'danger' });
    return { status: 'forbidden', data };
  }

  if (response.ok) {
    const contentType = response.headers.get('content-type') || '';
    if (contentType.includes('text/html')) {
      await replaceDocumentWithHtml(response);
      return { status: 'html' };
    }
    // JSON success from a legacy endpoint — reload to refresh page state
    window.location.reload();
    return { status: 'reloaded' };
  }

  // Validation / other errors: prefer showing HTML body when present
  const contentType = response.headers.get('content-type') || '';
  if (contentType.includes('text/html')) {
    await replaceDocumentWithHtml(response);
    return { status: 'html_error' };
  }

  const data = await parseJsonSafe(response);
  notify({
    message: data?.error?.message || __('Request failed'),
    type: 'danger',
  });
  return { status: 'error', data };
};

const buildMethodLinkRequest = link => {
  const method = (link.dataset.method || 'post').toUpperCase();
  const url = link.href;

  return () => {
    const body = new URLSearchParams();
    body.set(csrfParam(), csrfToken());
    if (method !== 'GET' && method !== 'POST') {
      body.set('_method', method.toLowerCase());
    }

    return {
      url,
      options: {
        method: method === 'GET' ? 'GET' : 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        },
        body: method === 'GET' ? undefined : body.toString(),
      },
    };
  };
};

const buildFormRequest = (form, submitter) => () => {
  const formData = new FormData(form);
  if (submitter && submitter.name) {
    formData.append(submitter.name, submitter.value ?? '');
  }
  if (!formData.has(csrfParam()) && csrfToken()) {
    formData.set(csrfParam(), csrfToken());
  }

  const method = (form.getAttribute('method') || 'POST').toUpperCase();
  let url = form.getAttribute('action') || window.location.href;

  // Rails method override on forms
  const override = formData.get('_method');
  const httpMethod = override
    ? 'POST'
    : method === 'GET'
    ? 'GET'
    : method;

  if (httpMethod === 'GET') {
    const qs = new URLSearchParams(formData).toString();
    url = qs ? `${url}${url.includes('?') ? '&' : '?'}${qs}` : url;
    return { url, options: { method: 'GET' } };
  }

  return {
    url,
    options: {
      method: httpMethod,
      body: formData,
      // Let the browser set multipart Content-Type + boundary
    },
  };
};

const onMethodLinkClick = async event => {
  const link = event.target.closest?.('a[data-method]');
  if (!link || !document.contains(link)) return;
  if (link.getAttribute(HANDLED_ATTR) === '1') return;
  if (event.defaultPrevented) return;
  if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
  if (event.button !== 0) return;

  // Opt-out for links that must keep native UJS (rare)
  if (link.dataset.foremanReauth === 'false') return;

  event.preventDefault();
  event.stopImmediatePropagation();

  const confirmMsg = link.dataset.confirm;
  const method = (link.dataset.method || 'post').toLowerCase();
  const isDelete = method === 'delete';

  try {
    if (confirmMsg) {
      await promptApplicationConfirm({
        title: isDelete ? __('Delete') : __('Confirm'),
        message: confirmMsg,
        isWarning: isDelete,
        confirmButtonText: isDelete ? __('Delete') : __('Confirm'),
      });
    }

    await submitLegacyWithReauth(buildMethodLinkRequest(link), 0, {
      contextMessage: confirmMsg || null,
    });
  } catch (e) {
    if (
      e?.message === 'reauthentication_cancelled' ||
      e?.message === 'confirm_cancelled'
    ) {
      return;
    }
    if (e?.message === 'reauthentication_modal_unavailable') {
      // Fall back to native navigation so fail-closed flash still works
      link.setAttribute(HANDLED_ATTR, '1');
      link.click();
      return;
    }
    notify({
      message: e?.message || __('Request failed'),
      type: 'danger',
    });
  }
};

const onReauthFormSubmit = async event => {
  const form = event.target;
  if (!(form instanceof HTMLFormElement)) return;
  if (form.dataset.foremanReauth !== 'true' && form.dataset.foremanReauth !== '1')
    return;
  if (event.defaultPrevented) return;

  event.preventDefault();
  event.stopImmediatePropagation();

  const submitter = event.submitter || null;

  try {
    await submitLegacyWithReauth(buildFormRequest(form, submitter));
  } catch (e) {
    if (e?.message === 'reauthentication_cancelled') return;
    notify({
      message: e?.message || __('Request failed'),
      type: 'danger',
    });
  }
};

/**
 * Install capture-phase listeners once (bundle load).
 */
export const installLegacyReauthentication = () => {
  if (installed || typeof document === 'undefined') return;
  installed = true;
  document.addEventListener('click', onMethodLinkClick, true);
  document.addEventListener('submit', onReauthFormSubmit, true);
};

export const _test = {
  buildMethodLinkRequest,
  buildFormRequest,
  csrfToken,
  MAX_REAUTH_RETRIES,
  promptApplicationConfirm,
};
