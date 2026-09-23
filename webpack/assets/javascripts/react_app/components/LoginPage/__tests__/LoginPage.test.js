import React from 'react';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import '@testing-library/jest-dom';

import LoginPage from '../LoginPage';
import { caption, logoSrc, token } from '../LoginPage.fixtures';

const renderLoginPage = (overrides = {}) => {
  render(
    <LoginPage
      caption={caption}
      logoSrc={logoSrc}
      token={token}
      {...overrides}
    />
  );
};

const getAlertCloseButton = () =>
  screen.queryByRole('button', { name: /^Close/i });

describe('LoginPage', () => {
  it('renders login page', () => {
    renderLoginPage({ alerts: null });

    expect(screen.getByText('Welcome')).toBeInTheDocument();
    expect(screen.getByText('Log in to your account')).toBeInTheDocument();
    expect(screen.getByText('some caption')).toBeInTheDocument();
    expect(screen.getByPlaceholderText('Username')).toBeInTheDocument();
    expect(screen.getByPlaceholderText('Password')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Log In' })).toBeDisabled();
  });

  it('renders submit error alert', () => {
    renderLoginPage({ alerts: { error: 'some-error' } });

    expect(screen.getByText('some-error')).toBeInTheDocument();
    expect(getAlertCloseButton()).not.toBeInTheDocument();
  });

  it('renders dismissible warning alert', async () => {
    renderLoginPage({ alerts: { warning: 'some-warning' } });

    expect(screen.getByText('some-warning')).toBeInTheDocument();

    await userEvent.click(getAlertCloseButton());

    expect(screen.queryByText('some-warning')).not.toBeInTheDocument();
  });

  it('enables log in when username and password are entered', async () => {
    renderLoginPage({ alerts: null });

    const submitButton = screen.getByRole('button', { name: 'Log In' });
    expect(submitButton).toBeDisabled();

    await userEvent.type(screen.getByPlaceholderText('Username'), 'admin');
    await userEvent.type(screen.getByPlaceholderText('Password'), 'secret');

    expect(submitButton).toBeEnabled();
  });

  it('does not render Turnstile widget when captcha disabled', () => {
    renderLoginPage({ captcha: { enabled: false } });
    expect(
      document.querySelector('[data-ouia-component-id="login-captcha"]')
    ).not.toBeInTheDocument();
    expect(
      document.querySelector('input[name="login[captcha_response]"]')
    ).not.toBeInTheDocument();
  });

  it('renders Turnstile container and site key when captcha enabled', () => {
    const renderMock = jest.fn(() => 'widget-1');
    window.turnstile = {
      render: renderMock,
      reset: jest.fn(),
    };
    renderLoginPage({
      captcha: {
        enabled: true,
        provider: 'turnstile',
        siteKey: 'public-site-key-only',
      },
    });
    expect(
      document.querySelector('[data-ouia-component-id="login-captcha"]')
    ).toBeInTheDocument();
    expect(
      document.querySelector('input[name="login[captcha_response]"]')
    ).toBeInTheDocument();
    expect(renderMock).toHaveBeenCalled();
    expect(renderMock.mock.calls[0][1].sitekey).toBe('public-site-key-only');
    // Secret must never appear in LoginPage DOM / bootstrap HTML.
    expect(document.body.innerHTML).not.toMatch(/secret[_-]?key/i);
    expect(document.body.innerHTML).not.toContain('server-secret');
    delete window.turnstile;
  });
});
