import React from 'react';
import { mount } from 'enzyme';
import LoginPage from '../LoginPage';
import { props } from '../LoginPage.fixtures';
import { testComponentSnapshotsWithFixtures } from '../../../common/testHelpers';

const fixtures = {
  'renders LoginPage': props,
};
describe('LoginPage', () => {
  describe('rendering', () => {
    testComponentSnapshotsWithFixtures(LoginPage, fixtures);

    it('sets username semantic autocomplete and password autocomplete off', () => {
      const component = mount(<LoginPage {...props} />);
      const username = component.find('input#login_login').getDOMNode();
      const password = component.find('input#login_password').getDOMNode();
      expect(username.getAttribute('autocomplete')).toEqual('username');
      expect(password.getAttribute('autocomplete')).toEqual('off');
    });
  });
});
