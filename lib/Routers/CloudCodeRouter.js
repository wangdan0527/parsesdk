"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.CloudCodeRouter = void 0;

var _PromiseRouter = _interopRequireDefault(require("../PromiseRouter"));

var _node = _interopRequireDefault(require("parse/node"));

var _rest = _interopRequireDefault(require("../rest"));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

const triggers = require('../triggers');

const middleware = require('../middlewares');

function formatJobSchedule(job_schedule) {
  if (typeof job_schedule.startAfter === 'undefined') {
    job_schedule.startAfter = new Date().toISOString();
  }

  return job_schedule;
}

function validateJobSchedule(config, job_schedule) {
  const jobs = triggers.getJobs(config.applicationId) || {};

  if (job_schedule.jobName && !jobs[job_schedule.jobName]) {
    throw new _node.default.Error(_node.default.Error.INTERNAL_SERVER_ERROR, 'Cannot Schedule a job that is not deployed');
  }
}

class CloudCodeRouter extends _PromiseRouter.default {
  mountRoutes() {
    this.route('GET', '/cloud_code/jobs', middleware.promiseEnforceMasterKeyAccess, CloudCodeRouter.getJobs);
    this.route('GET', '/cloud_code/jobs/data', middleware.promiseEnforceMasterKeyAccess, CloudCodeRouter.getJobsData);
    this.route('POST', '/cloud_code/jobs', middleware.promiseEnforceMasterKeyAccess, CloudCodeRouter.createJob);
    this.route('PUT', '/cloud_code/jobs/:objectId', middleware.promiseEnforceMasterKeyAccess, CloudCodeRouter.editJob);
    this.route('DELETE', '/cloud_code/jobs/:objectId', middleware.promiseEnforceMasterKeyAccess, CloudCodeRouter.deleteJob);
  }

  static getJobs(req) {
    return _rest.default.find(req.config, req.auth, '_JobSchedule', {}, {}).then(scheduledJobs => {
      return {
        response: scheduledJobs.results
      };
    });
  }

  static getJobsData(req) {
    const config = req.config;
    const jobs = triggers.getJobs(config.applicationId) || {};
    return _rest.default.find(req.config, req.auth, '_JobSchedule', {}, {}).then(scheduledJobs => {
      return {
        response: {
          in_use: scheduledJobs.results.map(job => job.jobName),
          jobs: Object.keys(jobs)
        }
      };
    });
  }

  static createJob(req) {
    const {
      job_schedule
    } = req.body;
    validateJobSchedule(req.config, job_schedule);
    return _rest.default.create(req.config, req.auth, '_JobSchedule', formatJobSchedule(job_schedule), req.client);
  }

  static editJob(req) {
    const {
      objectId
    } = req.params;
    const {
      job_schedule
    } = req.body;
    validateJobSchedule(req.config, job_schedule);
    return _rest.default.update(req.config, req.auth, '_JobSchedule', {
      objectId
    }, formatJobSchedule(job_schedule)).then(response => {
      return {
        response
      };
    });
  }

  static deleteJob(req) {
    const {
      objectId
    } = req.params;
    return _rest.default.del(req.config, req.auth, '_JobSchedule', objectId).then(response => {
      return {
        response
      };
    });
  }

}

exports.CloudCodeRouter = CloudCodeRouter;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIi4uLy4uL3NyYy9Sb3V0ZXJzL0Nsb3VkQ29kZVJvdXRlci5qcyJdLCJuYW1lcyI6WyJ0cmlnZ2VycyIsInJlcXVpcmUiLCJtaWRkbGV3YXJlIiwiZm9ybWF0Sm9iU2NoZWR1bGUiLCJqb2Jfc2NoZWR1bGUiLCJzdGFydEFmdGVyIiwiRGF0ZSIsInRvSVNPU3RyaW5nIiwidmFsaWRhdGVKb2JTY2hlZHVsZSIsImNvbmZpZyIsImpvYnMiLCJnZXRKb2JzIiwiYXBwbGljYXRpb25JZCIsImpvYk5hbWUiLCJQYXJzZSIsIkVycm9yIiwiSU5URVJOQUxfU0VSVkVSX0VSUk9SIiwiQ2xvdWRDb2RlUm91dGVyIiwiUHJvbWlzZVJvdXRlciIsIm1vdW50Um91dGVzIiwicm91dGUiLCJwcm9taXNlRW5mb3JjZU1hc3RlcktleUFjY2VzcyIsImdldEpvYnNEYXRhIiwiY3JlYXRlSm9iIiwiZWRpdEpvYiIsImRlbGV0ZUpvYiIsInJlcSIsInJlc3QiLCJmaW5kIiwiYXV0aCIsInRoZW4iLCJzY2hlZHVsZWRKb2JzIiwicmVzcG9uc2UiLCJyZXN1bHRzIiwiaW5fdXNlIiwibWFwIiwiam9iIiwiT2JqZWN0Iiwia2V5cyIsImJvZHkiLCJjcmVhdGUiLCJjbGllbnQiLCJvYmplY3RJZCIsInBhcmFtcyIsInVwZGF0ZSIsImRlbCJdLCJtYXBwaW5ncyI6Ijs7Ozs7OztBQUFBOztBQUNBOztBQUNBOzs7O0FBQ0EsTUFBTUEsUUFBUSxHQUFHQyxPQUFPLENBQUMsYUFBRCxDQUF4Qjs7QUFDQSxNQUFNQyxVQUFVLEdBQUdELE9BQU8sQ0FBQyxnQkFBRCxDQUExQjs7QUFFQSxTQUFTRSxpQkFBVCxDQUEyQkMsWUFBM0IsRUFBeUM7QUFDdkMsTUFBSSxPQUFPQSxZQUFZLENBQUNDLFVBQXBCLEtBQW1DLFdBQXZDLEVBQW9EO0FBQ2xERCxJQUFBQSxZQUFZLENBQUNDLFVBQWIsR0FBMEIsSUFBSUMsSUFBSixHQUFXQyxXQUFYLEVBQTFCO0FBQ0Q7O0FBQ0QsU0FBT0gsWUFBUDtBQUNEOztBQUVELFNBQVNJLG1CQUFULENBQTZCQyxNQUE3QixFQUFxQ0wsWUFBckMsRUFBbUQ7QUFDakQsUUFBTU0sSUFBSSxHQUFHVixRQUFRLENBQUNXLE9BQVQsQ0FBaUJGLE1BQU0sQ0FBQ0csYUFBeEIsS0FBMEMsRUFBdkQ7O0FBQ0EsTUFBSVIsWUFBWSxDQUFDUyxPQUFiLElBQXdCLENBQUNILElBQUksQ0FBQ04sWUFBWSxDQUFDUyxPQUFkLENBQWpDLEVBQXlEO0FBQ3ZELFVBQU0sSUFBSUMsY0FBTUMsS0FBVixDQUNKRCxjQUFNQyxLQUFOLENBQVlDLHFCQURSLEVBRUosNENBRkksQ0FBTjtBQUlEO0FBQ0Y7O0FBRU0sTUFBTUMsZUFBTixTQUE4QkMsc0JBQTlCLENBQTRDO0FBQ2pEQyxFQUFBQSxXQUFXLEdBQUc7QUFDWixTQUFLQyxLQUFMLENBQ0UsS0FERixFQUVFLGtCQUZGLEVBR0VsQixVQUFVLENBQUNtQiw2QkFIYixFQUlFSixlQUFlLENBQUNOLE9BSmxCO0FBTUEsU0FBS1MsS0FBTCxDQUNFLEtBREYsRUFFRSx1QkFGRixFQUdFbEIsVUFBVSxDQUFDbUIsNkJBSGIsRUFJRUosZUFBZSxDQUFDSyxXQUpsQjtBQU1BLFNBQUtGLEtBQUwsQ0FDRSxNQURGLEVBRUUsa0JBRkYsRUFHRWxCLFVBQVUsQ0FBQ21CLDZCQUhiLEVBSUVKLGVBQWUsQ0FBQ00sU0FKbEI7QUFNQSxTQUFLSCxLQUFMLENBQ0UsS0FERixFQUVFLDRCQUZGLEVBR0VsQixVQUFVLENBQUNtQiw2QkFIYixFQUlFSixlQUFlLENBQUNPLE9BSmxCO0FBTUEsU0FBS0osS0FBTCxDQUNFLFFBREYsRUFFRSw0QkFGRixFQUdFbEIsVUFBVSxDQUFDbUIsNkJBSGIsRUFJRUosZUFBZSxDQUFDUSxTQUpsQjtBQU1EOztBQUVELFNBQU9kLE9BQVAsQ0FBZWUsR0FBZixFQUFvQjtBQUNsQixXQUFPQyxjQUNKQyxJQURJLENBQ0NGLEdBQUcsQ0FBQ2pCLE1BREwsRUFDYWlCLEdBQUcsQ0FBQ0csSUFEakIsRUFDdUIsY0FEdkIsRUFDdUMsRUFEdkMsRUFDMkMsRUFEM0MsRUFFSkMsSUFGSSxDQUVDQyxhQUFhLElBQUk7QUFDckIsYUFBTztBQUNMQyxRQUFBQSxRQUFRLEVBQUVELGFBQWEsQ0FBQ0U7QUFEbkIsT0FBUDtBQUdELEtBTkksQ0FBUDtBQU9EOztBQUVELFNBQU9YLFdBQVAsQ0FBbUJJLEdBQW5CLEVBQXdCO0FBQ3RCLFVBQU1qQixNQUFNLEdBQUdpQixHQUFHLENBQUNqQixNQUFuQjtBQUNBLFVBQU1DLElBQUksR0FBR1YsUUFBUSxDQUFDVyxPQUFULENBQWlCRixNQUFNLENBQUNHLGFBQXhCLEtBQTBDLEVBQXZEO0FBQ0EsV0FBT2UsY0FDSkMsSUFESSxDQUNDRixHQUFHLENBQUNqQixNQURMLEVBQ2FpQixHQUFHLENBQUNHLElBRGpCLEVBQ3VCLGNBRHZCLEVBQ3VDLEVBRHZDLEVBQzJDLEVBRDNDLEVBRUpDLElBRkksQ0FFQ0MsYUFBYSxJQUFJO0FBQ3JCLGFBQU87QUFDTEMsUUFBQUEsUUFBUSxFQUFFO0FBQ1JFLFVBQUFBLE1BQU0sRUFBRUgsYUFBYSxDQUFDRSxPQUFkLENBQXNCRSxHQUF0QixDQUEwQkMsR0FBRyxJQUFJQSxHQUFHLENBQUN2QixPQUFyQyxDQURBO0FBRVJILFVBQUFBLElBQUksRUFBRTJCLE1BQU0sQ0FBQ0MsSUFBUCxDQUFZNUIsSUFBWjtBQUZFO0FBREwsT0FBUDtBQU1ELEtBVEksQ0FBUDtBQVVEOztBQUVELFNBQU9hLFNBQVAsQ0FBaUJHLEdBQWpCLEVBQXNCO0FBQ3BCLFVBQU07QUFBRXRCLE1BQUFBO0FBQUYsUUFBbUJzQixHQUFHLENBQUNhLElBQTdCO0FBQ0EvQixJQUFBQSxtQkFBbUIsQ0FBQ2tCLEdBQUcsQ0FBQ2pCLE1BQUwsRUFBYUwsWUFBYixDQUFuQjtBQUNBLFdBQU91QixjQUFLYSxNQUFMLENBQ0xkLEdBQUcsQ0FBQ2pCLE1BREMsRUFFTGlCLEdBQUcsQ0FBQ0csSUFGQyxFQUdMLGNBSEssRUFJTDFCLGlCQUFpQixDQUFDQyxZQUFELENBSlosRUFLTHNCLEdBQUcsQ0FBQ2UsTUFMQyxDQUFQO0FBT0Q7O0FBRUQsU0FBT2pCLE9BQVAsQ0FBZUUsR0FBZixFQUFvQjtBQUNsQixVQUFNO0FBQUVnQixNQUFBQTtBQUFGLFFBQWVoQixHQUFHLENBQUNpQixNQUF6QjtBQUNBLFVBQU07QUFBRXZDLE1BQUFBO0FBQUYsUUFBbUJzQixHQUFHLENBQUNhLElBQTdCO0FBQ0EvQixJQUFBQSxtQkFBbUIsQ0FBQ2tCLEdBQUcsQ0FBQ2pCLE1BQUwsRUFBYUwsWUFBYixDQUFuQjtBQUNBLFdBQU91QixjQUNKaUIsTUFESSxDQUVIbEIsR0FBRyxDQUFDakIsTUFGRCxFQUdIaUIsR0FBRyxDQUFDRyxJQUhELEVBSUgsY0FKRyxFQUtIO0FBQUVhLE1BQUFBO0FBQUYsS0FMRyxFQU1IdkMsaUJBQWlCLENBQUNDLFlBQUQsQ0FOZCxFQVFKMEIsSUFSSSxDQVFDRSxRQUFRLElBQUk7QUFDaEIsYUFBTztBQUNMQSxRQUFBQTtBQURLLE9BQVA7QUFHRCxLQVpJLENBQVA7QUFhRDs7QUFFRCxTQUFPUCxTQUFQLENBQWlCQyxHQUFqQixFQUFzQjtBQUNwQixVQUFNO0FBQUVnQixNQUFBQTtBQUFGLFFBQWVoQixHQUFHLENBQUNpQixNQUF6QjtBQUNBLFdBQU9oQixjQUNKa0IsR0FESSxDQUNBbkIsR0FBRyxDQUFDakIsTUFESixFQUNZaUIsR0FBRyxDQUFDRyxJQURoQixFQUNzQixjQUR0QixFQUNzQ2EsUUFEdEMsRUFFSlosSUFGSSxDQUVDRSxRQUFRLElBQUk7QUFDaEIsYUFBTztBQUNMQSxRQUFBQTtBQURLLE9BQVA7QUFHRCxLQU5JLENBQVA7QUFPRDs7QUFuR2dEIiwic291cmNlc0NvbnRlbnQiOlsiaW1wb3J0IFByb21pc2VSb3V0ZXIgZnJvbSAnLi4vUHJvbWlzZVJvdXRlcic7XG5pbXBvcnQgUGFyc2UgZnJvbSAncGFyc2Uvbm9kZSc7XG5pbXBvcnQgcmVzdCBmcm9tICcuLi9yZXN0JztcbmNvbnN0IHRyaWdnZXJzID0gcmVxdWlyZSgnLi4vdHJpZ2dlcnMnKTtcbmNvbnN0IG1pZGRsZXdhcmUgPSByZXF1aXJlKCcuLi9taWRkbGV3YXJlcycpO1xuXG5mdW5jdGlvbiBmb3JtYXRKb2JTY2hlZHVsZShqb2Jfc2NoZWR1bGUpIHtcbiAgaWYgKHR5cGVvZiBqb2Jfc2NoZWR1bGUuc3RhcnRBZnRlciA9PT0gJ3VuZGVmaW5lZCcpIHtcbiAgICBqb2Jfc2NoZWR1bGUuc3RhcnRBZnRlciA9IG5ldyBEYXRlKCkudG9JU09TdHJpbmcoKTtcbiAgfVxuICByZXR1cm4gam9iX3NjaGVkdWxlO1xufVxuXG5mdW5jdGlvbiB2YWxpZGF0ZUpvYlNjaGVkdWxlKGNvbmZpZywgam9iX3NjaGVkdWxlKSB7XG4gIGNvbnN0IGpvYnMgPSB0cmlnZ2Vycy5nZXRKb2JzKGNvbmZpZy5hcHBsaWNhdGlvbklkKSB8fCB7fTtcbiAgaWYgKGpvYl9zY2hlZHVsZS5qb2JOYW1lICYmICFqb2JzW2pvYl9zY2hlZHVsZS5qb2JOYW1lXSkge1xuICAgIHRocm93IG5ldyBQYXJzZS5FcnJvcihcbiAgICAgIFBhcnNlLkVycm9yLklOVEVSTkFMX1NFUlZFUl9FUlJPUixcbiAgICAgICdDYW5ub3QgU2NoZWR1bGUgYSBqb2IgdGhhdCBpcyBub3QgZGVwbG95ZWQnXG4gICAgKTtcbiAgfVxufVxuXG5leHBvcnQgY2xhc3MgQ2xvdWRDb2RlUm91dGVyIGV4dGVuZHMgUHJvbWlzZVJvdXRlciB7XG4gIG1vdW50Um91dGVzKCkge1xuICAgIHRoaXMucm91dGUoXG4gICAgICAnR0VUJyxcbiAgICAgICcvY2xvdWRfY29kZS9qb2JzJyxcbiAgICAgIG1pZGRsZXdhcmUucHJvbWlzZUVuZm9yY2VNYXN0ZXJLZXlBY2Nlc3MsXG4gICAgICBDbG91ZENvZGVSb3V0ZXIuZ2V0Sm9ic1xuICAgICk7XG4gICAgdGhpcy5yb3V0ZShcbiAgICAgICdHRVQnLFxuICAgICAgJy9jbG91ZF9jb2RlL2pvYnMvZGF0YScsXG4gICAgICBtaWRkbGV3YXJlLnByb21pc2VFbmZvcmNlTWFzdGVyS2V5QWNjZXNzLFxuICAgICAgQ2xvdWRDb2RlUm91dGVyLmdldEpvYnNEYXRhXG4gICAgKTtcbiAgICB0aGlzLnJvdXRlKFxuICAgICAgJ1BPU1QnLFxuICAgICAgJy9jbG91ZF9jb2RlL2pvYnMnLFxuICAgICAgbWlkZGxld2FyZS5wcm9taXNlRW5mb3JjZU1hc3RlcktleUFjY2VzcyxcbiAgICAgIENsb3VkQ29kZVJvdXRlci5jcmVhdGVKb2JcbiAgICApO1xuICAgIHRoaXMucm91dGUoXG4gICAgICAnUFVUJyxcbiAgICAgICcvY2xvdWRfY29kZS9qb2JzLzpvYmplY3RJZCcsXG4gICAgICBtaWRkbGV3YXJlLnByb21pc2VFbmZvcmNlTWFzdGVyS2V5QWNjZXNzLFxuICAgICAgQ2xvdWRDb2RlUm91dGVyLmVkaXRKb2JcbiAgICApO1xuICAgIHRoaXMucm91dGUoXG4gICAgICAnREVMRVRFJyxcbiAgICAgICcvY2xvdWRfY29kZS9qb2JzLzpvYmplY3RJZCcsXG4gICAgICBtaWRkbGV3YXJlLnByb21pc2VFbmZvcmNlTWFzdGVyS2V5QWNjZXNzLFxuICAgICAgQ2xvdWRDb2RlUm91dGVyLmRlbGV0ZUpvYlxuICAgICk7XG4gIH1cblxuICBzdGF0aWMgZ2V0Sm9icyhyZXEpIHtcbiAgICByZXR1cm4gcmVzdFxuICAgICAgLmZpbmQocmVxLmNvbmZpZywgcmVxLmF1dGgsICdfSm9iU2NoZWR1bGUnLCB7fSwge30pXG4gICAgICAudGhlbihzY2hlZHVsZWRKb2JzID0+IHtcbiAgICAgICAgcmV0dXJuIHtcbiAgICAgICAgICByZXNwb25zZTogc2NoZWR1bGVkSm9icy5yZXN1bHRzLFxuICAgICAgICB9O1xuICAgICAgfSk7XG4gIH1cblxuICBzdGF0aWMgZ2V0Sm9ic0RhdGEocmVxKSB7XG4gICAgY29uc3QgY29uZmlnID0gcmVxLmNvbmZpZztcbiAgICBjb25zdCBqb2JzID0gdHJpZ2dlcnMuZ2V0Sm9icyhjb25maWcuYXBwbGljYXRpb25JZCkgfHwge307XG4gICAgcmV0dXJuIHJlc3RcbiAgICAgIC5maW5kKHJlcS5jb25maWcsIHJlcS5hdXRoLCAnX0pvYlNjaGVkdWxlJywge30sIHt9KVxuICAgICAgLnRoZW4oc2NoZWR1bGVkSm9icyA9PiB7XG4gICAgICAgIHJldHVybiB7XG4gICAgICAgICAgcmVzcG9uc2U6IHtcbiAgICAgICAgICAgIGluX3VzZTogc2NoZWR1bGVkSm9icy5yZXN1bHRzLm1hcChqb2IgPT4gam9iLmpvYk5hbWUpLFxuICAgICAgICAgICAgam9iczogT2JqZWN0LmtleXMoam9icyksXG4gICAgICAgICAgfSxcbiAgICAgICAgfTtcbiAgICAgIH0pO1xuICB9XG5cbiAgc3RhdGljIGNyZWF0ZUpvYihyZXEpIHtcbiAgICBjb25zdCB7IGpvYl9zY2hlZHVsZSB9ID0gcmVxLmJvZHk7XG4gICAgdmFsaWRhdGVKb2JTY2hlZHVsZShyZXEuY29uZmlnLCBqb2Jfc2NoZWR1bGUpO1xuICAgIHJldHVybiByZXN0LmNyZWF0ZShcbiAgICAgIHJlcS5jb25maWcsXG4gICAgICByZXEuYXV0aCxcbiAgICAgICdfSm9iU2NoZWR1bGUnLFxuICAgICAgZm9ybWF0Sm9iU2NoZWR1bGUoam9iX3NjaGVkdWxlKSxcbiAgICAgIHJlcS5jbGllbnRcbiAgICApO1xuICB9XG5cbiAgc3RhdGljIGVkaXRKb2IocmVxKSB7XG4gICAgY29uc3QgeyBvYmplY3RJZCB9ID0gcmVxLnBhcmFtcztcbiAgICBjb25zdCB7IGpvYl9zY2hlZHVsZSB9ID0gcmVxLmJvZHk7XG4gICAgdmFsaWRhdGVKb2JTY2hlZHVsZShyZXEuY29uZmlnLCBqb2Jfc2NoZWR1bGUpO1xuICAgIHJldHVybiByZXN0XG4gICAgICAudXBkYXRlKFxuICAgICAgICByZXEuY29uZmlnLFxuICAgICAgICByZXEuYXV0aCxcbiAgICAgICAgJ19Kb2JTY2hlZHVsZScsXG4gICAgICAgIHsgb2JqZWN0SWQgfSxcbiAgICAgICAgZm9ybWF0Sm9iU2NoZWR1bGUoam9iX3NjaGVkdWxlKVxuICAgICAgKVxuICAgICAgLnRoZW4ocmVzcG9uc2UgPT4ge1xuICAgICAgICByZXR1cm4ge1xuICAgICAgICAgIHJlc3BvbnNlLFxuICAgICAgICB9O1xuICAgICAgfSk7XG4gIH1cblxuICBzdGF0aWMgZGVsZXRlSm9iKHJlcSkge1xuICAgIGNvbnN0IHsgb2JqZWN0SWQgfSA9IHJlcS5wYXJhbXM7XG4gICAgcmV0dXJuIHJlc3RcbiAgICAgIC5kZWwocmVxLmNvbmZpZywgcmVxLmF1dGgsICdfSm9iU2NoZWR1bGUnLCBvYmplY3RJZClcbiAgICAgIC50aGVuKHJlc3BvbnNlID0+IHtcbiAgICAgICAgcmV0dXJuIHtcbiAgICAgICAgICByZXNwb25zZSxcbiAgICAgICAgfTtcbiAgICAgIH0pO1xuICB9XG59XG4iXX0=