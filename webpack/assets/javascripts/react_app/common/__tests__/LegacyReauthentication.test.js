jest.mock('../Reauthentication', () => {
  const actual = jest.requireActual('../Reauthentication');
  return {
    ...actual,
    promptReauthentication: jest.fn(),
  };
});

jest.mock('../../redux', () => ({
  __esModule: true,
  default: { dispatch: jest.fn() },
}));

jest.mock('../../components/ConfirmModal', () => ({
  openConfirmModal: jest.fn(payload => ({
    type: 'confirmModal/open',
    payload,
  })),
}));

jest.mock('../../../foreman_toast_notifications', () => ({
  notify: jest.fn(),
}));

const { notify } = require('../../../foreman_toast_notifications');
const store = require('../../redux').default;
const { openConfirmModal } = require('../../components/ConfirmModal');
const {
  submitLegacyWithReauth,
  promptApplicationConfirm,
  _test,
} = require('../LegacyReauthentication');
const Reauthentication = require('../Reauthentication');

describe('LegacyReauthentication adapter', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    global.fetch = jest.fn();
    document.head.innerHTML =
      '<meta name="csrf-token" content="test-csrf"><meta name="csrf-param" content="authenticity_token">';
  });

  afterEach(() => {
    delete global.fetch;
  });

  const reauthForbidden = () =>
    Promise.resolve({
      ok: false,
      status: 403,
      type: 'basic',
      headers: {
        get: name =>
          name.toLowerCase() === 'content-type' ? 'application/json' : null,
      },
      json: async () => ({
        error: {
          reauthentication_required: true,
          action: 'users.destroy',
          reauthentication_supported: true,
          message: 'Re-authentication required to perform this action.',
        },
      }),
    });

  const authzForbidden = () =>
    Promise.resolve({
      ok: false,
      status: 403,
      type: 'basic',
      headers: {
        get: name =>
          name.toLowerCase() === 'content-type' ? 'application/json' : null,
      },
      json: async () => ({
        error: {
          message: 'Not authorized',
        },
      }),
    });

  const redirectOk = () =>
    Promise.resolve({
      ok: false,
      status: 302,
      type: 'basic',
      headers: {
        get: name => (name.toLowerCase() === 'location' ? '/users' : null),
      },
    });

  test('opens modal when reauthentication_required then retries once', async () => {
    Reauthentication.promptReauthentication.mockResolvedValue(undefined);
    global.fetch
      .mockImplementationOnce(reauthForbidden)
      .mockImplementationOnce(redirectOk);

    delete window.location;
    window.location = { href: '' };

    const build = jest.fn(() => ({
      url: '/users/1',
      options: { method: 'POST', headers: {}, body: '_method=delete' },
    }));

    await submitLegacyWithReauth(build);

    expect(Reauthentication.promptReauthentication).toHaveBeenCalledTimes(1);
    expect(Reauthentication.promptReauthentication).toHaveBeenCalledWith({
      action: 'users.destroy',
      unsupported: false,
      contextMessage: undefined,
    });
    expect(global.fetch).toHaveBeenCalledTimes(2);
    expect(build).toHaveBeenCalledTimes(2);
    expect(window.location.href).toBe('/users');
  });

  test('wrong password / cancel does not retry original request', async () => {
    Reauthentication.promptReauthentication.mockRejectedValue(
      new Error('reauthentication_cancelled')
    );
    global.fetch.mockImplementationOnce(reauthForbidden);

    const build = jest.fn(() => ({
      url: '/users/1',
      options: { method: 'POST', body: '_method=delete' },
    }));

    await expect(submitLegacyWithReauth(build)).rejects.toThrow(
      'reauthentication_cancelled'
    );
    expect(global.fetch).toHaveBeenCalledTimes(1);
  });

  test('unsupported provider opens modal with unsupported flag and does not retry on cancel', async () => {
    Reauthentication.promptReauthentication.mockRejectedValue(
      new Error('reauthentication_cancelled')
    );
    global.fetch.mockImplementationOnce(() =>
      Promise.resolve({
        ok: false,
        status: 403,
        type: 'basic',
        headers: {
          get: name =>
            name.toLowerCase() === 'content-type' ? 'application/json' : null,
        },
        json: async () => ({
          error: {
            reauthentication_required: true,
            action: 'users.destroy',
            reauthentication_supported: false,
          },
        }),
      })
    );

    const build = jest.fn(() => ({
      url: '/users/1',
      options: { method: 'POST', body: '_method=delete' },
    }));

    await expect(submitLegacyWithReauth(build)).rejects.toThrow(
      'reauthentication_cancelled'
    );
    expect(Reauthentication.promptReauthentication).toHaveBeenCalledWith({
      action: 'users.destroy',
      unsupported: true,
      contextMessage: undefined,
    });
    expect(global.fetch).toHaveBeenCalledTimes(1);
  });

  test('second reauth_required after retry does not loop', async () => {
    Reauthentication.promptReauthentication.mockResolvedValue(undefined);
    global.fetch
      .mockImplementationOnce(reauthForbidden)
      .mockImplementationOnce(reauthForbidden);

    const build = jest.fn(() => ({
      url: '/users/1',
      options: { method: 'POST', body: '_method=delete' },
    }));

    await submitLegacyWithReauth(build);

    expect(Reauthentication.promptReauthentication).toHaveBeenCalledTimes(1);
    expect(global.fetch).toHaveBeenCalledTimes(2);
    expect(notify).toHaveBeenCalled();
  });

  test('authorization 403 does not open modal', async () => {
    global.fetch.mockImplementationOnce(authzForbidden);

    const build = jest.fn(() => ({
      url: '/users/1',
      options: { method: 'POST', body: '_method=delete' },
    }));

    await submitLegacyWithReauth(build);

    expect(Reauthentication.promptReauthentication).not.toHaveBeenCalled();
    expect(global.fetch).toHaveBeenCalledTimes(1);
    expect(notify).toHaveBeenCalled();
  });

  test('sends X-Foreman-Accept-Reauth header', async () => {
    global.fetch.mockImplementationOnce(redirectOk);
    delete window.location;
    window.location = { href: '' };

    await submitLegacyWithReauth(() => ({
      url: '/users/1',
      options: { method: 'POST', headers: {}, body: '_method=delete' },
    }));

    const [, options] = global.fetch.mock.calls[0];
    expect(options.headers.get('X-Foreman-Accept-Reauth')).toBe('1');
    expect(options.headers.get('X-CSRF-Token')).toBe('test-csrf');
  });

  test('buildMethodLinkRequest preserves DELETE via _method', () => {
    document.body.innerHTML =
      '<a href="/users/9" data-method="delete" id="del">Delete</a>';
    const link = document.getElementById('del');
    const built = _test.buildMethodLinkRequest(link)();
    expect(built.options.method).toBe('POST');
    expect(built.options.body).toContain('_method=delete');
    expect(built.options.body).toContain('authenticity_token=test-csrf');
  });

  test('promptApplicationConfirm dispatches PatternFly confirm modal not window.confirm', async () => {
    const confirmSpy = jest.spyOn(window, 'confirm');
    store.dispatch.mockImplementation(action => {
      action.payload.onConfirm();
      return action;
    });

    await promptApplicationConfirm({
      title: 'Delete',
      message: 'Delete ali?',
      isWarning: true,
      confirmButtonText: 'Delete',
    });

    expect(openConfirmModal).toHaveBeenCalled();
    expect(store.dispatch).toHaveBeenCalled();
    expect(confirmSpy).not.toHaveBeenCalled();
    confirmSpy.mockRestore();
  });

  test('passes confirm contextMessage into reauth prompt', async () => {
    Reauthentication.promptReauthentication.mockResolvedValue(undefined);
    global.fetch
      .mockImplementationOnce(reauthForbidden)
      .mockImplementationOnce(redirectOk);
    delete window.location;
    window.location = { href: '' };

    await submitLegacyWithReauth(
      () => ({
        url: '/users/1',
        options: { method: 'POST', body: '_method=delete' },
      }),
      0,
      { contextMessage: 'Delete ali?' }
    );

    expect(Reauthentication.promptReauthentication).toHaveBeenCalledWith({
      action: 'users.destroy',
      unsupported: false,
      contextMessage: 'Delete ali?',
    });
  });
});

describe('actionDisplayLabel', () => {
  const { actionDisplayLabel } = require('../Reauthentication');

  test('maps users.destroy to human label not raw key', () => {
    expect(actionDisplayLabel('users.destroy')).toBe('Delete user');
    expect(actionDisplayLabel('users.destroy')).not.toBe('users.destroy');
  });
});
