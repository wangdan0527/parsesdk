'use strict'; // Helper functions for accessing the vkontakte API.

const httpsRequest = require('./httpsRequest');

var Parse = require('parse/node').Parse;

var logger = require('../../logger').default; // Returns a promise that fulfills iff this user id is valid.


function validateAuthData(authData, params) {
  return vkOAuth2Request(params).then(function (response) {
    if (response && response.access_token) {
      return request('api.vk.com', 'method/users.get?access_token=' + authData.access_token + '&v=5.8').then(function (response) {
        if (response && response.response && response.response.length && response.response[0].id == authData.id) {
          return;
        }

        throw new Parse.Error(Parse.Error.OBJECT_NOT_FOUND, 'Vk auth is invalid for this user.');
      });
    }

    logger.error('Vk Auth', 'Vk appIds or appSecret is incorrect.');
    throw new Parse.Error(Parse.Error.OBJECT_NOT_FOUND, 'Vk appIds or appSecret is incorrect.');
  });
}

function vkOAuth2Request(params) {
  return new Promise(function (resolve) {
    if (!params || !params.appIds || !params.appIds.length || !params.appSecret || !params.appSecret.length) {
      logger.error('Vk Auth', 'Vk auth is not configured. Missing appIds or appSecret.');
      throw new Parse.Error(Parse.Error.OBJECT_NOT_FOUND, 'Vk auth is not configured. Missing appIds or appSecret.');
    }

    resolve();
  }).then(function () {
    return request('oauth.vk.com', 'access_token?client_id=' + params.appIds + '&client_secret=' + params.appSecret + '&v=5.59&grant_type=client_credentials');
  });
} // Returns a promise that fulfills iff this app id is valid.


function validateAppId() {
  return Promise.resolve();
} // A promisey wrapper for api requests


function request(host, path) {
  return httpsRequest.get('https://' + host + '/' + path);
}

module.exports = {
  validateAppId: validateAppId,
  validateAuthData: validateAuthData
};
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIi4uLy4uLy4uL3NyYy9BZGFwdGVycy9BdXRoL3Zrb250YWt0ZS5qcyJdLCJuYW1lcyI6WyJodHRwc1JlcXVlc3QiLCJyZXF1aXJlIiwiUGFyc2UiLCJsb2dnZXIiLCJkZWZhdWx0IiwidmFsaWRhdGVBdXRoRGF0YSIsImF1dGhEYXRhIiwicGFyYW1zIiwidmtPQXV0aDJSZXF1ZXN0IiwidGhlbiIsInJlc3BvbnNlIiwiYWNjZXNzX3Rva2VuIiwicmVxdWVzdCIsImxlbmd0aCIsImlkIiwiRXJyb3IiLCJPQkpFQ1RfTk9UX0ZPVU5EIiwiZXJyb3IiLCJQcm9taXNlIiwicmVzb2x2ZSIsImFwcElkcyIsImFwcFNlY3JldCIsInZhbGlkYXRlQXBwSWQiLCJob3N0IiwicGF0aCIsImdldCIsIm1vZHVsZSIsImV4cG9ydHMiXSwibWFwcGluZ3MiOiJBQUFBLGEsQ0FFQTs7QUFFQSxNQUFNQSxZQUFZLEdBQUdDLE9BQU8sQ0FBQyxnQkFBRCxDQUE1Qjs7QUFDQSxJQUFJQyxLQUFLLEdBQUdELE9BQU8sQ0FBQyxZQUFELENBQVAsQ0FBc0JDLEtBQWxDOztBQUNBLElBQUlDLE1BQU0sR0FBR0YsT0FBTyxDQUFDLGNBQUQsQ0FBUCxDQUF3QkcsT0FBckMsQyxDQUVBOzs7QUFDQSxTQUFTQyxnQkFBVCxDQUEwQkMsUUFBMUIsRUFBb0NDLE1BQXBDLEVBQTRDO0FBQzFDLFNBQU9DLGVBQWUsQ0FBQ0QsTUFBRCxDQUFmLENBQXdCRSxJQUF4QixDQUE2QixVQUFTQyxRQUFULEVBQW1CO0FBQ3JELFFBQUlBLFFBQVEsSUFBSUEsUUFBUSxDQUFDQyxZQUF6QixFQUF1QztBQUNyQyxhQUFPQyxPQUFPLENBQ1osWUFEWSxFQUVaLG1DQUFtQ04sUUFBUSxDQUFDSyxZQUE1QyxHQUEyRCxRQUYvQyxDQUFQLENBR0xGLElBSEssQ0FHQSxVQUFTQyxRQUFULEVBQW1CO0FBQ3hCLFlBQ0VBLFFBQVEsSUFDUkEsUUFBUSxDQUFDQSxRQURULElBRUFBLFFBQVEsQ0FBQ0EsUUFBVCxDQUFrQkcsTUFGbEIsSUFHQUgsUUFBUSxDQUFDQSxRQUFULENBQWtCLENBQWxCLEVBQXFCSSxFQUFyQixJQUEyQlIsUUFBUSxDQUFDUSxFQUp0QyxFQUtFO0FBQ0E7QUFDRDs7QUFDRCxjQUFNLElBQUlaLEtBQUssQ0FBQ2EsS0FBVixDQUNKYixLQUFLLENBQUNhLEtBQU4sQ0FBWUMsZ0JBRFIsRUFFSixtQ0FGSSxDQUFOO0FBSUQsT0FoQk0sQ0FBUDtBQWlCRDs7QUFDRGIsSUFBQUEsTUFBTSxDQUFDYyxLQUFQLENBQWEsU0FBYixFQUF3QixzQ0FBeEI7QUFDQSxVQUFNLElBQUlmLEtBQUssQ0FBQ2EsS0FBVixDQUNKYixLQUFLLENBQUNhLEtBQU4sQ0FBWUMsZ0JBRFIsRUFFSixzQ0FGSSxDQUFOO0FBSUQsR0F6Qk0sQ0FBUDtBQTBCRDs7QUFFRCxTQUFTUixlQUFULENBQXlCRCxNQUF6QixFQUFpQztBQUMvQixTQUFPLElBQUlXLE9BQUosQ0FBWSxVQUFTQyxPQUFULEVBQWtCO0FBQ25DLFFBQ0UsQ0FBQ1osTUFBRCxJQUNBLENBQUNBLE1BQU0sQ0FBQ2EsTUFEUixJQUVBLENBQUNiLE1BQU0sQ0FBQ2EsTUFBUCxDQUFjUCxNQUZmLElBR0EsQ0FBQ04sTUFBTSxDQUFDYyxTQUhSLElBSUEsQ0FBQ2QsTUFBTSxDQUFDYyxTQUFQLENBQWlCUixNQUxwQixFQU1FO0FBQ0FWLE1BQUFBLE1BQU0sQ0FBQ2MsS0FBUCxDQUNFLFNBREYsRUFFRSx5REFGRjtBQUlBLFlBQU0sSUFBSWYsS0FBSyxDQUFDYSxLQUFWLENBQ0piLEtBQUssQ0FBQ2EsS0FBTixDQUFZQyxnQkFEUixFQUVKLHlEQUZJLENBQU47QUFJRDs7QUFDREcsSUFBQUEsT0FBTztBQUNSLEdBbEJNLEVBa0JKVixJQWxCSSxDQWtCQyxZQUFXO0FBQ2pCLFdBQU9HLE9BQU8sQ0FDWixjQURZLEVBRVosNEJBQ0VMLE1BQU0sQ0FBQ2EsTUFEVCxHQUVFLGlCQUZGLEdBR0ViLE1BQU0sQ0FBQ2MsU0FIVCxHQUlFLHVDQU5VLENBQWQ7QUFRRCxHQTNCTSxDQUFQO0FBNEJELEMsQ0FFRDs7O0FBQ0EsU0FBU0MsYUFBVCxHQUF5QjtBQUN2QixTQUFPSixPQUFPLENBQUNDLE9BQVIsRUFBUDtBQUNELEMsQ0FFRDs7O0FBQ0EsU0FBU1AsT0FBVCxDQUFpQlcsSUFBakIsRUFBdUJDLElBQXZCLEVBQTZCO0FBQzNCLFNBQU94QixZQUFZLENBQUN5QixHQUFiLENBQWlCLGFBQWFGLElBQWIsR0FBb0IsR0FBcEIsR0FBMEJDLElBQTNDLENBQVA7QUFDRDs7QUFFREUsTUFBTSxDQUFDQyxPQUFQLEdBQWlCO0FBQ2ZMLEVBQUFBLGFBQWEsRUFBRUEsYUFEQTtBQUVmakIsRUFBQUEsZ0JBQWdCLEVBQUVBO0FBRkgsQ0FBakIiLCJzb3VyY2VzQ29udGVudCI6WyIndXNlIHN0cmljdCc7XG5cbi8vIEhlbHBlciBmdW5jdGlvbnMgZm9yIGFjY2Vzc2luZyB0aGUgdmtvbnRha3RlIEFQSS5cblxuY29uc3QgaHR0cHNSZXF1ZXN0ID0gcmVxdWlyZSgnLi9odHRwc1JlcXVlc3QnKTtcbnZhciBQYXJzZSA9IHJlcXVpcmUoJ3BhcnNlL25vZGUnKS5QYXJzZTtcbnZhciBsb2dnZXIgPSByZXF1aXJlKCcuLi8uLi9sb2dnZXInKS5kZWZhdWx0O1xuXG4vLyBSZXR1cm5zIGEgcHJvbWlzZSB0aGF0IGZ1bGZpbGxzIGlmZiB0aGlzIHVzZXIgaWQgaXMgdmFsaWQuXG5mdW5jdGlvbiB2YWxpZGF0ZUF1dGhEYXRhKGF1dGhEYXRhLCBwYXJhbXMpIHtcbiAgcmV0dXJuIHZrT0F1dGgyUmVxdWVzdChwYXJhbXMpLnRoZW4oZnVuY3Rpb24ocmVzcG9uc2UpIHtcbiAgICBpZiAocmVzcG9uc2UgJiYgcmVzcG9uc2UuYWNjZXNzX3Rva2VuKSB7XG4gICAgICByZXR1cm4gcmVxdWVzdChcbiAgICAgICAgJ2FwaS52ay5jb20nLFxuICAgICAgICAnbWV0aG9kL3VzZXJzLmdldD9hY2Nlc3NfdG9rZW49JyArIGF1dGhEYXRhLmFjY2Vzc190b2tlbiArICcmdj01LjgnXG4gICAgICApLnRoZW4oZnVuY3Rpb24ocmVzcG9uc2UpIHtcbiAgICAgICAgaWYgKFxuICAgICAgICAgIHJlc3BvbnNlICYmXG4gICAgICAgICAgcmVzcG9uc2UucmVzcG9uc2UgJiZcbiAgICAgICAgICByZXNwb25zZS5yZXNwb25zZS5sZW5ndGggJiZcbiAgICAgICAgICByZXNwb25zZS5yZXNwb25zZVswXS5pZCA9PSBhdXRoRGF0YS5pZFxuICAgICAgICApIHtcbiAgICAgICAgICByZXR1cm47XG4gICAgICAgIH1cbiAgICAgICAgdGhyb3cgbmV3IFBhcnNlLkVycm9yKFxuICAgICAgICAgIFBhcnNlLkVycm9yLk9CSkVDVF9OT1RfRk9VTkQsXG4gICAgICAgICAgJ1ZrIGF1dGggaXMgaW52YWxpZCBmb3IgdGhpcyB1c2VyLidcbiAgICAgICAgKTtcbiAgICAgIH0pO1xuICAgIH1cbiAgICBsb2dnZXIuZXJyb3IoJ1ZrIEF1dGgnLCAnVmsgYXBwSWRzIG9yIGFwcFNlY3JldCBpcyBpbmNvcnJlY3QuJyk7XG4gICAgdGhyb3cgbmV3IFBhcnNlLkVycm9yKFxuICAgICAgUGFyc2UuRXJyb3IuT0JKRUNUX05PVF9GT1VORCxcbiAgICAgICdWayBhcHBJZHMgb3IgYXBwU2VjcmV0IGlzIGluY29ycmVjdC4nXG4gICAgKTtcbiAgfSk7XG59XG5cbmZ1bmN0aW9uIHZrT0F1dGgyUmVxdWVzdChwYXJhbXMpIHtcbiAgcmV0dXJuIG5ldyBQcm9taXNlKGZ1bmN0aW9uKHJlc29sdmUpIHtcbiAgICBpZiAoXG4gICAgICAhcGFyYW1zIHx8XG4gICAgICAhcGFyYW1zLmFwcElkcyB8fFxuICAgICAgIXBhcmFtcy5hcHBJZHMubGVuZ3RoIHx8XG4gICAgICAhcGFyYW1zLmFwcFNlY3JldCB8fFxuICAgICAgIXBhcmFtcy5hcHBTZWNyZXQubGVuZ3RoXG4gICAgKSB7XG4gICAgICBsb2dnZXIuZXJyb3IoXG4gICAgICAgICdWayBBdXRoJyxcbiAgICAgICAgJ1ZrIGF1dGggaXMgbm90IGNvbmZpZ3VyZWQuIE1pc3NpbmcgYXBwSWRzIG9yIGFwcFNlY3JldC4nXG4gICAgICApO1xuICAgICAgdGhyb3cgbmV3IFBhcnNlLkVycm9yKFxuICAgICAgICBQYXJzZS5FcnJvci5PQkpFQ1RfTk9UX0ZPVU5ELFxuICAgICAgICAnVmsgYXV0aCBpcyBub3QgY29uZmlndXJlZC4gTWlzc2luZyBhcHBJZHMgb3IgYXBwU2VjcmV0LidcbiAgICAgICk7XG4gICAgfVxuICAgIHJlc29sdmUoKTtcbiAgfSkudGhlbihmdW5jdGlvbigpIHtcbiAgICByZXR1cm4gcmVxdWVzdChcbiAgICAgICdvYXV0aC52ay5jb20nLFxuICAgICAgJ2FjY2Vzc190b2tlbj9jbGllbnRfaWQ9JyArXG4gICAgICAgIHBhcmFtcy5hcHBJZHMgK1xuICAgICAgICAnJmNsaWVudF9zZWNyZXQ9JyArXG4gICAgICAgIHBhcmFtcy5hcHBTZWNyZXQgK1xuICAgICAgICAnJnY9NS41OSZncmFudF90eXBlPWNsaWVudF9jcmVkZW50aWFscydcbiAgICApO1xuICB9KTtcbn1cblxuLy8gUmV0dXJucyBhIHByb21pc2UgdGhhdCBmdWxmaWxscyBpZmYgdGhpcyBhcHAgaWQgaXMgdmFsaWQuXG5mdW5jdGlvbiB2YWxpZGF0ZUFwcElkKCkge1xuICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlKCk7XG59XG5cbi8vIEEgcHJvbWlzZXkgd3JhcHBlciBmb3IgYXBpIHJlcXVlc3RzXG5mdW5jdGlvbiByZXF1ZXN0KGhvc3QsIHBhdGgpIHtcbiAgcmV0dXJuIGh0dHBzUmVxdWVzdC5nZXQoJ2h0dHBzOi8vJyArIGhvc3QgKyAnLycgKyBwYXRoKTtcbn1cblxubW9kdWxlLmV4cG9ydHMgPSB7XG4gIHZhbGlkYXRlQXBwSWQ6IHZhbGlkYXRlQXBwSWQsXG4gIHZhbGlkYXRlQXV0aERhdGE6IHZhbGlkYXRlQXV0aERhdGEsXG59O1xuIl19