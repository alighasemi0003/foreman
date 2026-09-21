import { API } from '../';
import IntegrationTestHelper from '../../../common/IntegrationTestHelper';
import { action, key, postActionWithCallback } from '../APIFixtures';
import { apiRequest } from '../APIRequest';

const data = { results: [1] };
jest.mock('../');

const mockPrompt = jest.fn();
jest.mock('../../../common/Reauthentication', () => {
  const actual = jest.requireActual('../../../common/Reauthentication');
  return {
    ...actual,
    promptReauthentication: (...args) => mockPrompt(...args),
  };
});

describe('API get', () => {
  const store = {
    dispatch: jest.fn(),
    getState: jest.fn(() => ({
      intervals: { [key]: 1 },
      API: {
        INITIAL_RESOURCE: { response: { results: [2] } },
      },
    })),
  };
  beforeEach(() => {
    store.dispatch = jest.fn();
    mockPrompt.mockReset();
  });

  it('should dispatch request and success actions on resolve', async () => {
    const apiSuccessResponse = { data };
    API.get.mockImplementation(
      () =>
        new Promise((resolve, reject) => {
          resolve(apiSuccessResponse);
        })
    );
    const modifiedAction = { ...action };
    modifiedAction.payload.handleSuccess = jest.fn();
    apiRequest(modifiedAction, store);
    await IntegrationTestHelper.flushAllPromises();
    expect(modifiedAction.payload.handleSuccess.mock.calls).toMatchSnapshot();
    expect(store.dispatch.mock.calls).toMatchSnapshot();
  });

  it('should dispatch request and failure actions on reject', async () => {
    const apiError = new Error('bad request');
    API.get.mockImplementation(
      () =>
        new Promise((resolve, reject) => {
          reject(apiError);
        })
    );
    const modifiedAction = { ...action };
    modifiedAction.payload.handleError = jest.fn();
    apiRequest(modifiedAction, store);
    await IntegrationTestHelper.flushAllPromises();
    expect(modifiedAction.payload.handleError.mock.calls).toMatchSnapshot();
    expect(store.dispatch.mock.calls).toMatchSnapshot();
  });

  it('should dispatch stop interval on API error', async () => {
    const apiError = new Error('bad request');
    API.get.mockImplementation(
      () =>
        new Promise((resolve, reject) => {
          reject(apiError);
        })
    );
    const modifiedAction = { ...action };
    modifiedAction.payload.handleError = jest.fn();
    apiRequest(modifiedAction, store);
    await IntegrationTestHelper.flushAllPromises();
    expect(modifiedAction.payload.handleError.mock.calls).toMatchSnapshot();
    expect(store.dispatch.mock.calls).toMatchSnapshot();
  });

  it('should dispatch a success toast notification on API resolve', async () => {
    const apiSuccessResponse = { data };
    API.get.mockImplementation(
      () =>
        new Promise((resolve, reject) => {
          resolve(apiSuccessResponse);
        })
    );
    const modifiedAction = { ...action };
    modifiedAction.payload.successToast = jest.fn(
      () => 'Your API request was successful!'
    );
    apiRequest(modifiedAction, store);
    await IntegrationTestHelper.flushAllPromises();
    expect(modifiedAction.payload.successToast).toHaveBeenLastCalledWith(
      apiSuccessResponse
    );
    expect(store.dispatch.mock.calls).toMatchSnapshot();
  });

  it('should dispatch an error toast notification on API failure', async () => {
    const apiError = new Error('bad request');
    API.get.mockImplementation(
      () =>
        new Promise((resolve, reject) => {
          reject(apiError);
        })
    );
    const modifiedAction = { ...action };
    modifiedAction.payload.errorToast = jest.fn(
      error =>
        `Oh no! Something went wrong, server returned the error: ${error.message}`
    );
    apiRequest(modifiedAction, store);
    await IntegrationTestHelper.flushAllPromises();
    expect(modifiedAction.payload.errorToast).toHaveBeenLastCalledWith(
      apiError
    );
    expect(store.dispatch.mock.calls).toMatchSnapshot();
  });

  it('should dispatch an update if an updateData callback exists', async () => {
    const apiSuccessResponse = { data };
    API.post.mockImplementation(
      () =>
        new Promise(resolve => {
          resolve(apiSuccessResponse);
        })
    );
    apiRequest(postActionWithCallback, store);
    await IntegrationTestHelper.flushAllPromises();
    expect(store.dispatch.mock.calls).toMatchSnapshot();
  });
});

describe('API reauthentication retry', () => {
  const store = {
    dispatch: jest.fn(),
    getState: jest.fn(() => ({
      intervals: {},
      API: {},
    })),
  };

  beforeEach(() => {
    store.dispatch = jest.fn();
    mockPrompt.mockReset();
    API.post.mockReset();
    API.get.mockReset();
  });

  const reauthError = () => {
    const err = new Error('Forbidden');
    err.response = {
      status: 403,
      data: {
        error: {
          reauthentication_required: true,
          action: 'users.destroy',
          reauthentication_supported: true,
        },
      },
    };
    return err;
  };

  it('prompts and retries once on explicit reauthentication_required', async () => {
    mockPrompt.mockResolvedValue(undefined);
    API.post
      .mockRejectedValueOnce(reauthError())
      .mockResolvedValueOnce({ data: { ok: true } });

    const handleSuccess = jest.fn();
    const handleError = jest.fn();
    await apiRequest(
      {
        type: 'API_POST',
        payload: {
          key: 'DESTROY_USER',
          url: '/api/users/1',
          params: {},
          handleSuccess,
          handleError,
        },
      },
      store
    );
    await IntegrationTestHelper.flushAllPromises();

    expect(mockPrompt).toHaveBeenCalledTimes(1);
    expect(API.post).toHaveBeenCalledTimes(2);
    expect(handleSuccess).toHaveBeenCalledTimes(1);
    expect(handleError).not.toHaveBeenCalled();
  });

  it('does not intercept ordinary 403 without reauthentication_required', async () => {
    const err = new Error('Forbidden');
    err.response = { status: 403, data: { error: { message: 'Nope' } } };
    API.post.mockRejectedValue(err);

    const handleError = jest.fn();
    await apiRequest(
      {
        type: 'API_POST',
        payload: {
          key: 'DESTROY_USER',
          url: '/api/users/1',
          params: {},
          handleError,
        },
      },
      store
    );
    await IntegrationTestHelper.flushAllPromises();

    expect(mockPrompt).not.toHaveBeenCalled();
    expect(API.post).toHaveBeenCalledTimes(1);
    expect(handleError).toHaveBeenCalledTimes(1);
  });

  it('does not recurse for /users/reauthenticate failures', async () => {
    const err = new Error('Unauthorized');
    err.response = {
      status: 401,
      data: {
        status: 'authentication_failed',
        error: { reauthentication_required: true },
      },
    };
    API.post.mockRejectedValue(err);
    const handleError = jest.fn();
    await apiRequest(
      {
        type: 'API_POST',
        payload: {
          key: 'REAUTH',
          url: '/users/reauthenticate',
          params: { password: 'x' },
          handleError,
        },
      },
      store
    );
    await IntegrationTestHelper.flushAllPromises();

    expect(mockPrompt).not.toHaveBeenCalled();
    expect(API.post).toHaveBeenCalledTimes(1);
  });

  it('cancel does not retry original mutation', async () => {
    mockPrompt.mockRejectedValue(new Error('reauthentication_cancelled'));
    API.post.mockRejectedValue(reauthError());
    const handleError = jest.fn();
    await apiRequest(
      {
        type: 'API_POST',
        payload: {
          key: 'DESTROY_USER',
          url: '/api/users/1',
          params: {},
          handleError,
        },
      },
      store
    );
    await IntegrationTestHelper.flushAllPromises();

    expect(mockPrompt).toHaveBeenCalledTimes(1);
    expect(API.post).toHaveBeenCalledTimes(1);
    expect(handleError).toHaveBeenCalledTimes(1);
  });
});
