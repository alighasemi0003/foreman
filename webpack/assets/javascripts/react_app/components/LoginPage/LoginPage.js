import React, { useState } from 'react';
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

const LoginPage = ({
  alerts,
  caption,
  logoSrc,
  token,
  captchaEnabled,
  captchaQuestion,
}) => {
  const { modifiedAlerts, submitErrors } = adjustAlerts(alerts);

  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [captchaAnswer, setCaptchaAnswer] = useState('');
  const [isLoginDisabled, setIsLoginDisabled] = useState(true);
  const [isLoading, setIsLoading] = useState(false);
  const [alertArr, setAlertArr] = useState(modifiedAlerts);
  const closeAlert = index => {
    const other = alertArr.filter((_, i) => i !== index);
    setAlertArr(other);
  };

  const handleUsernameChange = (_event, value) => {
    setUsername(value);
    validateForm(value, password, captchaAnswer);
  };

  const handlePasswordChange = (_event, value) => {
    setPassword(value);
    validateForm(username, value, captchaAnswer);
  };

  const handleCaptchaChange = (_event, value) => {
    setCaptchaAnswer(value);
    validateForm(username, password, value);
  };

  const validateForm = (user, pass, captcha) => {
    const hasUsername = user !== '';
    const hasPassword = pass !== '';
    const hasCaptcha = !captchaEnabled || captcha !== '';
    setIsLoginDisabled(!(hasUsername && hasPassword && hasCaptcha));
  };

  const refreshCaptcha = () => {
    // Reload page to get a new CAPTCHA question
    window.location.reload();
  };

  const handleSubmit = () => {
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
              <AlertActionCloseButton onClose={() => closeAlert(index)} />
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
      {captchaEnabled && captchaQuestion && (
        <FormGroup
          isRequired
          fieldId="captcha"
          label={__('CAPTCHA')}
          helperText={__('Solve the math problem')}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '10px' }}>
            <div style={{ fontSize: '16px', fontWeight: 'bold', padding: '8px 12px', border: '1px solid #ccc', borderRadius: '4px', backgroundColor: '#f5f5f5' }}>
              {captchaQuestion}
            </div>
            <Button
              variant="link"
              onClick={refreshCaptcha}
              aria-label={__('Refresh CAPTCHA')}
            >
              {__('Refresh')}
            </Button>
          </div>
          <TextInput
            ouiaId="login-captcha"
            isRequired
            type="text"
            value={captchaAnswer}
            onChange={handleCaptchaChange}
            id="login_captcha_answer"
            name="login[captcha_answer]"
            placeholder={__('Enter your answer')}
            autoComplete="off"
            maxLength={10}
          />
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
  captchaEnabled: PropTypes.bool,
  captchaQuestion: PropTypes.string,
};

LoginPage.defaultProps = {
  alerts: null,
  backgroundUrl: null,
  caption: null,
  logoSrc: null,
  captchaEnabled: false,
  captchaQuestion: null,
};

export default LoginPage;
