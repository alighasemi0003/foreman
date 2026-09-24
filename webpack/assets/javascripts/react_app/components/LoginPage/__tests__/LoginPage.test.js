import React from 'react';
import { render, screen, waitFor } from '@testing-library/react';
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

  it('does not render local CAPTCHA when captcha disabled', () => {
    renderLoginPage({ captcha: { enabled: false } });
    expect(
      document.querySelector('[data-ouia-component-id="login-captcha"]')
    ).not.toBeInTheDocument();
    expect(
      document.querySelector('input[name="login[captcha_response]"]')
    ).not.toBeInTheDocument();
  });

  it('renders local CAPTCHA question and answer field when enabled', async () => {
    renderLoginPage({
      captcha: {
        enabled: true,
        provider: 'local',
        question: 'What is 12 + 34?',
        refreshPath: '/users/captcha_challenge',
      },
    });
    expect(
      document.querySelector('[data-ouia-component-id="login-captcha"]')
    ).toBeInTheDocument();
    expect(screen.getByText('What is 12 + 34?')).toBeInTheDocument();
    expect(
      document.querySelector('input[name="login[captcha_response]"]')
    ).toBeInTheDocument();
    expect(document.body.innerHTML).not.toMatch(/answer.?digest|login_captcha/i);

    const submitButton = screen.getByRole('button', { name: 'Log In' });
    await userEvent.type(screen.getByPlaceholderText('Username'), 'admin');
    await userEvent.type(screen.getByPlaceholderText('Password'), 'secret');
    expect(submitButton).toBeDisabled();
    await userEvent.type(screen.getByLabelText(/CAPTCHA answer/i), '46');
    expect(submitButton).toBeEnabled();
  });

  it('refresh requests a new CAPTCHA challenge', async () => {
    global.fetch = jest.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        enabled: true,
        provider: 'local',
        question: 'What is 5 + 6?',
      }),
    });
    renderLoginPage({
      captcha: {
        enabled: true,
        provider: 'local',
        question: 'What is 1 + 2?',
        refreshPath: '/users/captcha_challenge',
      },
    });
    await userEvent.click(
      screen.getByRole('button', { name: /Refresh CAPTCHA/i })
    );
    await waitFor(() => {
      expect(screen.getByText('What is 5 + 6?')).toBeInTheDocument();
    });
    expect(global.fetch).toHaveBeenCalledWith(
      '/users/captcha_challenge',
      expect.objectContaining({ method: 'GET' })
    );
    delete global.fetch;
  });
});
