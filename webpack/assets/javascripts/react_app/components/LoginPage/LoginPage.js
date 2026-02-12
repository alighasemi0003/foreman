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

const LoginPage = ({
  alerts,
  caption,
  logoSrc,
  token,
  captchaEnabled,
  captchaNewUrl,
}) => {
  const { modifiedAlerts, submitErrors } = adjustAlerts(alerts);

  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [captchaCode, setCaptchaCode] = useState('');
  const [captchaKey, setCaptchaKey] = useState('');
  const [captchaImageUrl, setCaptchaImageUrl] = useState('');
  const [isLoginDisabled, setIsLoginDisabled] = useState(true);
  const [isLoading, setIsLoading] = useState(false);
  const [alertArr, setAlertArr] = useState(modifiedAlerts);
  const closeAlert = index => {
    const other = alertArr.filter((_, i) => i !== index);
    setAlertArr(other);
  };

  const fetchNewCaptcha = () => {
    if (!captchaNewUrl) return;
    setCaptchaCode('');
    fetch(captchaNewUrl)
      .then(res => res.json())
      .then(data => {
        setCaptchaKey(data.captcha_key || '');
        setCaptchaImageUrl(data.captcha_image_url || '');
      })
      .catch(() => {
        setCaptchaKey('');
        setCaptchaImageUrl('');
      });
  };

  useEffect(() => {
    if (captchaEnabled && captchaNewUrl) fetchNewCaptcha();
  }, [captchaEnabled, captchaNewUrl]);

  const handleUsernameChange = (_event, value) => {
    setUsername(value);
    validateForm(value, password, captchaCode);
  };

  const handlePasswordChange = (_event, value) => {
    setPassword(value);
    validateForm(username, value, captchaCode);
  };

  const handleCaptchaChange = (_event, value) => {
    setCaptchaCode(value);
    validateForm(username, password, value);
  };

  const validateForm = (user, pass, captcha) => {
    const hasUsername = user !== '';
    const hasPassword = pass !== '';
    const hasCaptcha = !captchaEnabled || captcha !== '';
    setIsLoginDisabled(!(hasUsername && hasPassword && hasCaptcha));
  };

  const refreshCaptchaImage = () => {
    fetchNewCaptcha();
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
      {captchaEnabled && captchaNewUrl && (
        <FormGroup
          isRequired
          fieldId="captcha"
          label={__('CAPTCHA')}
          helperText={__('Enter the characters shown in the image')}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '10px' }}>
            {captchaImageUrl ? (
              <img
                src={captchaImageUrl}
                alt={__('CAPTCHA image')}
                style={{ border: '1px solid #ccc', borderRadius: '4px' }}
              />
            ) : null}
            <Button
              variant="link"
              onClick={refreshCaptchaImage}
              aria-label={__('Refresh CAPTCHA')}
            >
              {__('Refresh')}
            </Button>
          </div>
          <input type="hidden" name="login[captcha_key]" value={captchaKey} />
          <TextInput
            ouiaId="login-captcha"
            isRequired
            type="text"
            value={captchaCode}
            onChange={handleCaptchaChange}
            id="login_captcha"
            name="login[captcha]"
            placeholder={__('Enter CAPTCHA code')}
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
  captchaNewUrl: PropTypes.string,
};

LoginPage.defaultProps = {
  alerts: null,
  backgroundUrl: null,
  caption: null,
  logoSrc: null,
  captchaEnabled: false,
  captchaNewUrl: null,
};

export default LoginPage;
