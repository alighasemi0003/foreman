import React, { useState, useEffect } from 'react';
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

const LoginPage = ({ alerts, caption, logoSrc, token, captcha }) => {
  const { modifiedAlerts, submitErrors } = adjustAlerts(alerts);

  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [captchaAnswer, setCaptchaAnswer] = useState('');
  const [captchaQuestion, setCaptchaQuestion] = useState(
    (captcha && captcha.question) || ''
  );
  const [captchaError, setCaptchaError] = useState(false);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [isLoginDisabled, setIsLoginDisabled] = useState(true);
  const [isLoading, setIsLoading] = useState(false);
  const [alertArr, setAlertArr] = useState(modifiedAlerts);

  const captchaEnabled = !!(captcha && captcha.enabled);
  const captchaReady =
    !captchaEnabled || (!!captchaAnswer.trim() && !!captchaQuestion && !captchaError);

  const updateSubmitDisabled = (user, pass, challengeOk) => {
    setIsLoginDisabled(!(user !== '' && pass !== '' && challengeOk));
  };

  const closeAlert = index => {
    const other = alertArr.filter((_, i) => i !== index);
    setAlertArr(other);
  };

  const refreshCaptcha = async () => {
    if (!captchaEnabled) return;
    setIsRefreshing(true);
    setCaptchaError(false);
    setCaptchaAnswer('');
    try {
      const path = (captcha && captcha.refreshPath) || '/users/captcha_challenge';
      const response = await fetch(path, {
        method: 'GET',
        credentials: 'same-origin',
        headers: { Accept: 'application/json' },
      });
      if (!response.ok) {
        throw new Error('refresh_failed');
      }
      const data = await response.json();
      if (!data.question) {
        throw new Error('missing_question');
      }
      setCaptchaQuestion(data.question);
      updateSubmitDisabled(username, password, false);
    } catch (e) {
      setCaptchaError(true);
      setCaptchaQuestion('');
      setIsLoginDisabled(true);
    } finally {
      setIsRefreshing(false);
    }
  };

  // After a failed login (server re-render with error), clear answer so user
  // must use the newly issued question from props / refresh.
  useEffect(() => {
    if (submitErrors.length > 0 && captchaEnabled) {
      setCaptchaAnswer('');
      if (captcha && captcha.question) {
        setCaptchaQuestion(captcha.question);
      }
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (captcha && captcha.question) {
      setCaptchaQuestion(captcha.question);
    }
  }, [captcha && captcha.question]);

  const handleUsernameChange = (_event, value) => {
    setUsername(value);
    const ready =
      !captchaEnabled ||
      (!!captchaAnswer.trim() && !!captchaQuestion && !captchaError);
    updateSubmitDisabled(value, password, ready);
  };

  const handlePasswordChange = (_event, value) => {
    setPassword(value);
    const ready =
      !captchaEnabled ||
      (!!captchaAnswer.trim() && !!captchaQuestion && !captchaError);
    updateSubmitDisabled(username, value, ready);
  };

  const handleCaptchaChange = (_event, value) => {
    setCaptchaAnswer(value);
    const ready =
      !captchaEnabled ||
      (!!value.trim() && !!captchaQuestion && !captchaError);
    updateSubmitDisabled(username, password, ready);
  };

  const handleSubmit = event => {
    if (captchaEnabled && (!captchaAnswer.trim() || !captchaQuestion || captchaError)) {
      event.preventDefault();
      setCaptchaError(true);
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
        <FormGroup
          isRequired
          fieldId="login-captcha"
          label={captchaQuestion || __('CAPTCHA challenge')}
        >
          <div data-ouia-component-id="login-captcha">
            <TextInput
              ouiaId="login-captcha-answer"
              isRequired
              type="text"
              name="login[captcha_response]"
              value={captchaAnswer}
              autoComplete="off"
              aria-label={__('CAPTCHA answer')}
              placeholder={__('Answer')}
              onChange={handleCaptchaChange}
              isDisabled={captchaError && !captchaQuestion}
            />
            <Button
              ouiaId="login-captcha-refresh"
              variant="link"
              type="button"
              isInline
              isDisabled={isRefreshing}
              onClick={refreshCaptcha}
              aria-label={__('Refresh CAPTCHA')}
            >
              {__('Refresh CAPTCHA')}
            </Button>
          </div>
          {captchaError && (
            <Alert
              ouiaId="login-captcha-error"
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
    question: PropTypes.string,
    refreshPath: PropTypes.string,
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
