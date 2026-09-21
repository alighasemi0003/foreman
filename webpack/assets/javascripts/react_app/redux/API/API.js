import axios from 'axios';
import './APITestSetup';
import { foremanUrl } from '../../common/helpers';

const getcsrfToken = () => {
  const token = document.querySelector('meta[name="csrf-token"]');

  return token ? token.content : '';
};

axios.defaults.headers.common['X-Requested-With'] = 'XMLHttpRequest';
axios.defaults.headers.common['X-CSRF-Token'] = getcsrfToken();

// Always refresh CSRF from the live meta tag. Module-load defaults can be
// empty/stale (e.g. Module Federation eval timing), which breaks POSTs such as
// /users/reauthenticate and surfaces as a generic "Authentication failed".
axios.interceptors.request.use(config => {
  const token = getcsrfToken();
  if (token) {
    config.headers = config.headers || {};
    config.headers['X-CSRF-Token'] = token;
  }
  return config;
});

export default {
  get(url, headers = {}, params = {}) {
    return axios.get(foremanUrl(url), {
      headers,
      params,
    });
  },
  put(url, data = {}, headers = {}) {
    return axios.put(foremanUrl(url), data, {
      headers,
    });
  },
  post(url, data = {}, headers = {}) {
    return axios.post(foremanUrl(url), data, {
      headers,
    });
  },
  delete(url, headers = {}) {
    return axios.delete(foremanUrl(url), {
      headers,
    });
  },
  patch(url, data = {}, headers = {}) {
    return axios.patch(foremanUrl(url), data, {
      headers,
    });
  },
};
