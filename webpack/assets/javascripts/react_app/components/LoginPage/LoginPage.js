import React, { useState, useEffect, useRef } from 'react';
import PropTypes from 'prop-types';
import {
  LoginPage as PF5LoginPage,
  Form,
  FormGroup,
  TextInput,
  ActionGroup,
  Button,
  Alert,
  AlertActionCloseButton,
  FormAlert,
} from '@patternfly/react-core';

import { translate as __ } from '../../common/I18n';
import { adjustAlerts, defaultFormProps } from './helpers';
import './LoginPage.scss';

const TURNSTILE_SCRIPT =
  'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';

const LoginPage = ({ alerts, caption, logoSrc, token, captcha }) => {
  const { modifiedAlerts, submitErrors } = adjustAlerts(alerts);

  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [captchaToken, setCaptchaToken] = useState('');
  const [captchaLoadError, setCaptchaLoadError] = useState(false);
  const [isLoginDisabled, setIsLoginDisabled] = useState(true);
  const [isLoading, setIsLoading] = useState(false);
  const [alertArr, setAlertArr] = useState(modifiedAlerts);
  const widgetIdRef = useRef(null);
  const containerRef = useRef(null);

  const captchaEnabled = !!(captcha && captcha.enabled && captcha.siteKey);
  const captchaReady = !captchaEnabled || (!!captchaToken && !captchaLoadError);

  const updateSubmitDisabled = (user, pass, challengeOk) => {
    setIsLoginDisabled(!(user !== '' && pass !== '' && challengeOk));
  };

  const closeAlert = index => {
    const other = alertArr.filter((_, i) => i !== index);
    setAlertArr(other);
  };

  const resetCaptchaWidget = () => {
    setCaptchaToken('');
    if (
      captchaEnabled &&
      window.turnstile &&
      widgetIdRef.current !== null
    ) {
      try {
        window.turnstile.reset(widgetIdRef.current);
      } catch (e) {
        // ignore reset errors; server will fail closed without a fresh token
      }
    }
  };

  useEffect(() => {
    if (!captchaEnabled) {
      return undefined;
    }

    let cancelled = false;

    const renderWidget = () => {
      if (cancelled || !containerRef.current || !window.turnstile) {
        return;
      }
      try {
        widgetIdRef.current = window.turnstile.render(containerRef.current, {
          sitekey: captcha.siteKey,
          callback: value => {
            setCaptchaToken(value || '');
            setCaptchaLoadError(false);
            setIsLoginDisabled(!(username && password && value));
          },
          'expired-callback': () => {
            setCaptchaToken('');
            setIsLoginDisabled(true);
          },
          'error-callback': () => {
            setCaptchaToken('');
            setCaptchaLoadError(true);
            setIsLoginDisabled(true);
          },
        });
      } catch (e) {
        setCaptchaLoadError(true);
      }
    };

    // API already present (e.g. prior load or test stub) — render without reloading.
    if (window.turnstile) {
      renderWidget();
      return () => {
        cancelled = true;
      };
    }

    const existing = document.querySelector(
      `script[src="${TURNSTILE_SCRIPT}"]`
    );
    if (existing) {
      existing.addEventListener('load', renderWidget);
      existing.addEventListener('error', () => {
        if (!cancelled) setCaptchaLoadError(true);
      });
      return () => {
        cancelled = true;
      };
    }

    const script = document.createElement('script');
    script.src = TURNSTILE_SCRIPT;
    script.async = true;
    script.onload = () => renderWidget();
    script.onerror = () => {
      if (!cancelled) setCaptchaLoadError(true);
    };
    document.body.appendChild(script);

    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps -- mount once for challenge
  }, [captchaEnabled, captcha && captcha.siteKey]);

  // After a failed login (server re-render with error), reset challenge token.
  useEffect(() => {
    if (submitErrors.length > 0 && captchaEnabled) {
      resetCaptchaWidget();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleUsernameChange = (_event, value) => {
    setUsername(value);
    updateSubmitDisabled(value, password, captchaReady);
  };

  const handlePasswordChange = (_event, value) => {
    setPassword(value);
    updateSubmitDisabled(username, value, captchaReady);
  };

  const handleSubmit = event => {
    if (captchaEnabled && (!captchaToken || captchaLoadError)) {
      event.preventDefault();
      setCaptchaLoadError(true);
      setIsLoginDisabled(true);
      return;
    }
    setIsLoading(true);
    setTimeout(() => {
      setIsLoginDisabled(true);
    }, 10);
  };

  const loginForm = (
    <Form {...defaultFormProps.attributes}>
      {submitErrors.length > 0 && (
        <FormAlert>
          <Alert
            key="login-failed"
            ouiaId="login-alert"
            variant="danger"
            title={submitErrors}
            aria-live="polite"
            isInline
          />
        </FormAlert>
      )}
      {alertArr.length !== 0 &&
        alertArr.map((alert, index) => (
          <Alert
            key={index}
            variant={alert.type}
            title={alert.message}
            ouiaId="login-alert"
            actionClose={
              <AlertActionCloseButton
                ouiaId="login-alert-close-button"
                onClose={() => closeAlert(index)}
              />
            }
          />
        ))}
      <FormGroup isRequired fieldId="username">
        <TextInput
          ouiaId="login-username"
          isRequired
          type="text"
          value={username}
          autoComplete="username"
          onChange={handleUsernameChange}
          {...defaultFormProps.usernameField}
        />
      </FormGroup>
      <FormGroup isRequired fieldId="password">
        <TextInput
          ouiaId="login-password"
          isRequired
          type="password"
          value={password}
          autoComplete="current-password"
          onChange={handlePasswordChange}
          {...defaultFormProps.passwordField}
        />
      </FormGroup>
      {captchaEnabled && (
        <FormGroup fieldId="login-captcha">
          <div
            id="turnstile-container"
            ref={containerRef}
            data-ouia-component-id="login-captcha"
          />
          <input
            type="hidden"
            name="login[captcha_response]"
            value={captchaToken}
            readOnly
          />
          {captchaLoadError && (
            <Alert
              ouiaId="login-captcha-load-error"
              variant="danger"
              title={__(
                'CAPTCHA could not be loaded. Please retry or contact your administrator.'
              )}
              aria-live="polite"
              isInline
            />
          )}
        </FormGroup>
      )}
      <input name="authenticity_token" type="hidden" value={token} />
      <ActionGroup>
        <Button
          ouiaId="login-submit"
          type="submit"
          isBlock
          variant="primary"
          isDisabled={isLoginDisabled}
          isLoading={isLoading}
          onClick={handleSubmit}
        >
          {defaultFormProps.submitText}
        </Button>
      </ActionGroup>
    </Form>
  );

  return (
    <div id="login-page">
      <PF5LoginPage
        className="login-pf"
        brandImgSrc={logoSrc}
        loginTitle={__('Welcome')}
        loginSubtitle={__('Log in to your account')}
        textContent={caption}
      >
        {loginForm}
      </PF5LoginPage>
    </div>
  );
};

LoginPage.propTypes = {
  alerts: PropTypes.shape({
    success: PropTypes.string,
    warning: PropTypes.string,
    error: PropTypes.string,
  }),
  backgroundUrl: PropTypes.string,
  caption: PropTypes.string,
  logoSrc: PropTypes.string,
  token: PropTypes.string.isRequired,
  captcha: PropTypes.shape({
    enabled: PropTypes.bool,
    provider: PropTypes.string,
    siteKey: PropTypes.string,
  }),
};

LoginPage.defaultProps = {
  alerts: null,
  backgroundUrl: null,
  caption: null,
  logoSrc: null,
  captcha: { enabled: false },
};

export default LoginPage;
