/* eslint-disable camelcase */
import React, { useCallback, useEffect, useState } from 'react';
import ReactDOM from 'react-dom';
import {
  Button,
  Form,
  FormGroup,
  Modal,
  ModalVariant,
  TextInput,
} from '@patternfly/react-core';
import { translate as __ } from './I18n';
import { API } from '../redux/API';

const MODAL_HOST_ID = 'foreman-reauth-modal-host';
const PASSWORD_INPUT_ID = 'foreman-reauth-password';

let pendingResolve;
let pendingReject;
let setModalStateExternal;
let mounted = false;

const ensureHost = () => {
  let el = document.getElementById(MODAL_HOST_ID);
  if (!el) {
    el = document.createElement('div');
    el.id = MODAL_HOST_ID;
    document.body.appendChild(el);
  }
  return el;
};

const focusPassword = () => {
  setTimeout(() => document.getElementById(PASSWORD_INPUT_ID)?.focus?.(), 0);
};

/** Display labels only — not a security policy map. */
const ACTION_LABELS = {
  'users.destroy': () => __('Delete user'),
  'users.create': () => __('Create user'),
  'users.set_admin': () => __('Change administrator access'),
  'users.set_disabled': () => __('Change user status'),
  'users.impersonate': () => __('Impersonate user'),
  'users.terminate_sessions': () => __('Terminate sessions'),
  'users.invalidate_jwt': () => __('Invalidate registration tokens'),
  'users.change_password': () => __('Change password'),
  'users.change_roles': () => __('Change roles'),
  'auth_sources.create': () => __('Create authentication source'),
  'auth_sources.update': () => __('Update authentication source'),
  'auth_sources.destroy': () => __('Delete authentication source'),
  'ssh_keys.create': () => __('Add SSH key'),
  'ssh_keys.destroy': () => __('Delete SSH key'),
  'registration_commands.create': () => __('Generate registration command'),
  'personal_access_tokens.create': () => __('Create personal access token'),
  'personal_access_tokens.revoke': () => __('Revoke personal access token'),
  'key_pairs.download': () => __('Download key pair'),
  'key_pairs.recreate': () => __('Recreate key pair'),
  'key_pairs.destroy': () => __('Delete key pair'),
  'settings.reauthentication.update': () => __('Change re-authentication settings'),
  'settings.oauth_credentials.update': () => __('Change OAuth credentials'),
};

const DESTRUCTIVE_ACTIONS = new Set([
  'users.destroy',
  'auth_sources.destroy',
  'ssh_keys.destroy',
  'key_pairs.destroy',
  'personal_access_tokens.revoke',
  'users.terminate_sessions',
  'users.invalidate_jwt',
]);

export const actionDisplayLabel = actionKey => {
  if (!actionKey) return null;
  const fn = ACTION_LABELS[actionKey];
  return fn ? fn() : null;
};

export const isDestructiveAction = actionKey =>
  DESTRUCTIVE_ACTIONS.has(actionKey);

const csrfHeaders = () => {
  const token = document.querySelector('meta[name="csrf-token"]')?.content;
  return token ? { 'X-CSRF-Token': token } : {};
};

const ReauthModalApp = () => {
  const [open, setOpen] = useState(false);
  const [unsupported, setUnsupported] = useState(false);
  const [action, setAction] = useState(null);
  const [contextMessage, setContextMessage] = useState(null);
  const [password, setPassword] = useState('');
  const [error, setError] = useState(null);
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    setModalStateExternal = ({
      open: isOpen,
      unsupported: isUnsupported,
      action: actionKey,
      contextMessage: ctx,
    }) => {
      setOpen(isOpen);
      setUnsupported(!!isUnsupported);
      setAction(actionKey);
      setContextMessage(ctx || null);
      setPassword('');
      setError(null);
      setSubmitting(false);
    };
    return () => {
      setModalStateExternal = null;
    };
  }, []);

  useEffect(() => {
    if (open && !unsupported) focusPassword();
  }, [open, unsupported]);

  const close = useCallback(cancelled => {
    setOpen(false);
    if (cancelled && pendingReject) {
      pendingReject(new Error('reauthentication_cancelled'));
    }
    pendingResolve = null;
    pendingReject = null;
  }, []);

  const submit = async () => {
    if (submitting || !password) return;
    setSubmitting(true);
    setError(null);
    try {
      await API.post(
        '/users/reauthenticate',
        { password },
        csrfHeaders()
      );
      const resolve = pendingResolve;
      pendingResolve = null;
      pendingReject = null;
      setOpen(false);
      if (resolve) resolve();
    } catch (e) {
      const status = e.response?.data?.status;
      if (status === 'reauthentication_unsupported') {
        setUnsupported(true);
        setError(
          e.response?.data?.message ||
            __(
              'Re-authentication is not supported for your authentication source.'
            )
        );
      } else if (e.response?.status === 422) {
        // CSRF / unprocessable — do not imply wrong password
        setError(
          e.response?.data?.message ||
            __('Unable to verify authenticity. Refresh the page and try again.')
        );
      } else if (e.response) {
        // Backend auth / rate-limit / lockout responses
        setError(e.response?.data?.message || __('Authentication failed'));
      } else {
        // Client/runtime errors (e.g. broken import) — do not imply wrong password
        // eslint-disable-next-line no-console
        console.error('Re-authentication request failed', e);
        setError(__('Unable to complete re-authentication. Please try again.'));
      }
      setSubmitting(false);
      focusPassword();
    }
  };

  const label = actionDisplayLabel(action);
  const destructive = isDestructiveAction(action);
  const title = unsupported
    ? __('Re-authentication unavailable')
    : destructive && label
    ? label
    : __('Confirm your identity');

  return (
    <Modal
      variant={ModalVariant.small}
      title={title}
      isOpen={open}
      onClose={() => close(true)}
      actions={
        unsupported
          ? [
              <Button key="close" variant="primary" onClick={() => close(true)}>
                {__('Close')}
              </Button>,
            ]
          : [
              <Button
                key="confirm"
                variant={destructive ? 'danger' : 'primary'}
                onClick={submit}
                isDisabled={submitting || !password}
                isLoading={submitting}
              >
                {destructive && label ? label : __('Confirm')}
              </Button>,
              <Button key="cancel" variant="link" onClick={() => close(true)}>
                {__('Cancel')}
              </Button>,
            ]
      }
    >
      {unsupported ? (
        <p>
          {error ||
            __(
              'Re-authentication is not supported for your authentication source. Sign out and sign in again, or contact your administrator.'
            )}
        </p>
      ) : (
        <Form
          onSubmit={e => {
            e.preventDefault();
            submit();
          }}
        >
          {contextMessage && <p>{contextMessage}</p>}
          <p>
            {__(
              'This action requires recent confirmation of your identity. Enter your current password to continue.'
            )}
          </p>
          {label && !destructive && (
            <p>
              <strong>{__('Action')}:</strong> {label}
            </p>
          )}
          <FormGroup
            label={__('Password')}
            fieldId={PASSWORD_INPUT_ID}
            validated={error ? 'error' : 'default'}
          >
            <TextInput
              id={PASSWORD_INPUT_ID}
              type="password"
              value={password}
              onChange={(_e, val) => setPassword(val)}
              autoComplete="off"
              validated={error ? 'error' : 'default'}
              isDisabled={submitting}
            />
          </FormGroup>
          {error && (
            <p className="pf-v5-c-form__helper-text pf-m-error">{error}</p>
          )}
        </Form>
      )}
    </Modal>
  );
};

const mountModal = () => {
  if (mounted) return;
  ReactDOM.render(<ReauthModalApp />, ensureHost());
  mounted = true;
};

/**
 * Prompt for re-authentication. Resolves on success; rejects on cancel.
 * opts: { action, unsupported, contextMessage }
 */
export const promptReauthentication = (opts = {}) => {
  mountModal();
  return new Promise((resolve, reject) => {
    pendingResolve = resolve;
    pendingReject = reject;
    setTimeout(() => {
      if (setModalStateExternal) {
        setModalStateExternal({
          open: true,
          unsupported: !!opts.unsupported,
          action: opts.action,
          contextMessage: opts.contextMessage,
        });
      } else {
        reject(new Error('reauthentication_modal_unavailable'));
      }
    }, 0);
  });
};

export const isReauthenticationRequired = error => {
  const data = error?.response?.data?.error;
  return !!(data && data.reauthentication_required);
};

export const isReauthenticationRequiredPayload = data =>
  !!(data && data.error && data.error.reauthentication_required);

export const reauthenticationAction = error =>
  error?.response?.data?.error?.action;

export const reauthenticationActionFromPayload = data => data?.error?.action;

export const reauthenticationSupported = error => {
  const data = error?.response?.data?.error;
  if (!data || data.reauthentication_supported === undefined) {
    return true;
  }
  return !!data.reauthentication_supported;
};

export const reauthenticationSupportedFromPayload = data => {
  const inner = data?.error;
  if (!inner || inner.reauthentication_supported === undefined) {
    return true;
  }
  return !!inner.reauthentication_supported;
};
