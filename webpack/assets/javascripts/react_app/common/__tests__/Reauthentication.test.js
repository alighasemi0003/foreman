/**
 * Regression: Reauthentication must import named { API } from redux/API.
 * A default import from the barrel resolves to undefined at runtime and
 * surfaces as a false "Authentication failed" with no network request.
 */
import { act, fireEvent, screen, waitFor } from '@testing-library/react';

const mockPost = jest.fn();

jest.mock('../../redux/API', () => ({
  API: {
    post: (...args) => mockPost(...args),
    get: jest.fn(),
    put: jest.fn(),
    delete: jest.fn(),
    patch: jest.fn(),
  },
}));

jest.mock('../I18n', () => ({
  translate: msg => msg,
  sprintf: (fmt, ...args) => fmt,
}));

describe('Reauthentication modal submit', () => {
  let promptReauthentication;

  beforeEach(() => {
    jest.resetModules();
    mockPost.mockReset();
    document.body.innerHTML = '';
    document.head.innerHTML =
      '<meta name="csrf-token" content="test-csrf-token">';

    // global_test_setup rethrows console.error — silence act warnings + diagnostic log
    // eslint-disable-next-line no-console
    jest.spyOn(console, 'error').mockImplementation(() => {});

    // Fresh module so `mounted` is false; mock still applies after resetModules.
    // eslint-disable-next-line global-require
    ({ promptReauthentication } = require('../Reauthentication'));
  });

  afterEach(() => {
    // eslint-disable-next-line no-console
    console.error.mockRestore?.();
    const host = document.getElementById('foreman-reauth-modal-host');
    if (host) {
      // eslint-disable-next-line global-require
      const ReactDOM = require('react-dom');
      try {
        ReactDOM.unmountComponentAtNode(host);
      } catch (e) {
        // ignore
      }
      host.remove();
    }
  });

  it('resolves named API export (old default import would be undefined)', () => {
    // eslint-disable-next-line global-require
    const barrel = require('../../redux/API');
    expect(barrel.API).toBeDefined();
    expect(typeof barrel.API.post).toBe('function');
    expect(barrel.default).toBeUndefined();
  });

  it('POSTs /users/reauthenticate with password and resolves on success', async () => {
    mockPost.mockResolvedValue({ data: { status: 'success' } });

    let resolved = false;
    let promise;
    await act(async () => {
      promise = promptReauthentication({ action: 'users.destroy' });
      await new Promise(r => setTimeout(r, 0));
    });
    promise.then(() => {
      resolved = true;
    });

    await waitFor(() => {
      expect(document.getElementById('foreman-reauth-password')).toBeTruthy();
    });

    await act(async () => {
      fireEvent.change(document.getElementById('foreman-reauth-password'), {
        target: { value: 'CorrectHorse1!' },
      });
    });

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: /Delete user/i }));
    });

    await waitFor(() => {
      expect(mockPost).toHaveBeenCalledTimes(1);
    });

    expect(mockPost).toHaveBeenCalledWith(
      '/users/reauthenticate',
      { password: 'CorrectHorse1!' },
      expect.objectContaining({ 'X-CSRF-Token': 'test-csrf-token' })
    );

    await waitFor(() => {
      expect(resolved).toBe(true);
    });

    await waitFor(() => {
      expect(document.getElementById('foreman-reauth-password')).toBeFalsy();
    });
  });

  it('shows Authentication failed on backend 401 and keeps modal open', async () => {
    const err = new Error('Request failed');
    err.response = {
      status: 401,
      data: {
        status: 'authentication_failed',
        message: 'Authentication failed',
      },
    };
    mockPost.mockRejectedValue(err);

    await act(async () => {
      promptReauthentication({ action: 'users.destroy' });
      await new Promise(r => setTimeout(r, 0));
    });

    await waitFor(() => {
      expect(document.getElementById('foreman-reauth-password')).toBeTruthy();
    });

    await act(async () => {
      fireEvent.change(document.getElementById('foreman-reauth-password'), {
        target: { value: 'WrongPass1!' },
      });
    });

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: /Delete user/i }));
    });

    await waitFor(() => {
      expect(mockPost).toHaveBeenCalledTimes(1);
    });

    await waitFor(() => {
      expect(screen.getByText('Authentication failed')).toBeTruthy();
    });
    expect(document.getElementById('foreman-reauth-password')).toBeTruthy();
  });

  it('does not map client TypeError to Authentication failed', async () => {
    mockPost.mockRejectedValue(
      new TypeError("Cannot read properties of undefined (reading 'post')")
    );

    await act(async () => {
      promptReauthentication({ action: 'users.destroy' });
      await new Promise(r => setTimeout(r, 0));
    });

    await waitFor(() => {
      expect(document.getElementById('foreman-reauth-password')).toBeTruthy();
    });

    await act(async () => {
      fireEvent.change(document.getElementById('foreman-reauth-password'), {
        target: { value: 'AnyPass1!' },
      });
    });

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: /Delete user/i }));
    });

    await waitFor(() => {
      expect(
        screen.getByText(
          'Unable to complete re-authentication. Please try again.'
        )
      ).toBeTruthy();
    });
    expect(screen.queryByText('Authentication failed')).toBeNull();
  });
});
