/* eslint-disable no-console */
import { getApiResponse } from './APIHelpers';
import { actionTypeGenerator } from './APIActionTypeGenerator';
import { noop } from '../../common/helpers';
import {
  isReauthenticationRequired,
  promptReauthentication,
  reauthenticationAction,
  reauthenticationSupported,
} from '../../common/Reauthentication';
import { stopInterval } from '../middlewares/IntervalMiddleware';
import { selectDoesIntervalExist } from '../middlewares/IntervalMiddleware/IntervalSelectors';
import { selectAPIResponse } from './APISelectors';
import { addToast } from '../../components/ToastsList';

const MAX_REAUTH_RETRIES = 1;

export const apiRequest = async (
  {
    type,
    payload: {
      key,
      url,
      headers = {},
      params = {},
      actionTypes = {},
      handleError = noop,
      handleSuccess = noop,
      successToast,
      errorToast,
      payload = {},
      updateData,
    },
  },
  { dispatch, getState },
  reauthAttempt = 0
) => {
  const prevState = getState();
  const { REQUEST, SUCCESS, FAILURE, UPDATE } = actionTypeGenerator(
    key,
    actionTypes
  );
  const modifiedPayload = { ...payload, url };
  const stopIntervalCallback = selectDoesIntervalExist(prevState, key)
    ? () => dispatch(stopInterval(key))
    : () => console.warn(`There's no interval API request for the key: ${key}`);

  if (reauthAttempt === 0) {
    dispatch({
      type: REQUEST,
      key,
      payload: modifiedPayload,
    });
  }

  try {
    const response = await getApiResponse({ type, url, headers, params });

    dispatch({
      type: SUCCESS,
      key,
      payload: modifiedPayload,
      response: response.data,
    });

    updateData &&
      dispatch({
        type: UPDATE,
        key,
        payload: updateData(selectAPIResponse(prevState, key), response.data),
      });

    successToast &&
      dispatch(
        addToast({
          type: 'success',
          message: successToast(response),
          key: SUCCESS,
        })
      );

    handleSuccess(response, stopIntervalCallback);
  } catch (error) {
    if (
      isReauthenticationRequired(error) &&
      reauthAttempt < MAX_REAUTH_RETRIES
    ) {
      try {
        await promptReauthentication({
          action: reauthenticationAction(error),
          unsupported: !reauthenticationSupported(error),
        });
        return apiRequest(
          {
            type,
            payload: {
              key,
              url,
              headers,
              params,
              actionTypes,
              handleError,
              handleSuccess,
              successToast,
              errorToast,
              payload,
              updateData,
            },
          },
          { dispatch, getState },
          reauthAttempt + 1
        );
      } catch (reauthError) {
        // cancelled or failed — fall through to failure handling
      }
    }

    dispatch({
      type: FAILURE,
      key,
      payload: modifiedPayload,
      response: error,
    });

    errorToast &&
      dispatch(
        addToast({ type: 'danger', message: errorToast(error), key: FAILURE })
      );

    handleError(error, stopIntervalCallback);
  }
};
