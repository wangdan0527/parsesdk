"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.FilesRouter = void 0;

var _express = _interopRequireDefault(require("express"));

var _bodyParser = _interopRequireDefault(require("body-parser"));

var Middlewares = _interopRequireWildcard(require("../middlewares"));

var _node = _interopRequireDefault(require("parse/node"));

var _Config = _interopRequireDefault(require("../Config"));

var _mime = _interopRequireDefault(require("mime"));

var _logger = _interopRequireDefault(require("../logger"));

function _getRequireWildcardCache() { if (typeof WeakMap !== "function") return null; var cache = new WeakMap(); _getRequireWildcardCache = function () { return cache; }; return cache; }

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } var cache = _getRequireWildcardCache(); if (cache && cache.has(obj)) { return cache.get(obj); } var newObj = {}; if (obj != null) { var hasPropertyDescriptor = Object.defineProperty && Object.getOwnPropertyDescriptor; for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) { var desc = hasPropertyDescriptor ? Object.getOwnPropertyDescriptor(obj, key) : null; if (desc && (desc.get || desc.set)) { Object.defineProperty(newObj, key, desc); } else { newObj[key] = obj[key]; } } } } newObj.default = obj; if (cache) { cache.set(obj, newObj); } return newObj; }

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

class FilesRouter {
  expressRouter({
    maxUploadSize = '20Mb'
  } = {}) {
    var router = _express.default.Router();

    router.get('/files/:appId/:filename', this.getHandler);
    router.post('/files', function (req, res, next) {
      next(new _node.default.Error(_node.default.Error.INVALID_FILE_NAME, 'Filename not provided.'));
    });
    router.post('/files/:filename', _bodyParser.default.raw({
      type: () => {
        return true;
      },
      limit: maxUploadSize
    }), // Allow uploads without Content-Type, or with any Content-Type.
    Middlewares.handleParseHeaders, this.createHandler);
    router.delete('/files/:filename', Middlewares.handleParseHeaders, Middlewares.enforceMasterKeyAccess, this.deleteHandler);
    return router;
  }

  getHandler(req, res) {
    const config = _Config.default.get(req.params.appId);

    const filesController = config.filesController;
    const filename = req.params.filename;

    const contentType = _mime.default.getType(filename);

    if (isFileStreamable(req, filesController)) {
      filesController.handleFileStream(config, filename, req, res, contentType).catch(() => {
        res.status(404);
        res.set('Content-Type', 'text/plain');
        res.end('File not found.');
      });
    } else {
      filesController.getFileData(config, filename).then(data => {
        res.status(200);
        res.set('Content-Type', contentType);
        res.set('Content-Length', data.length);
        res.end(data);
      }).catch(() => {
        res.status(404);
        res.set('Content-Type', 'text/plain');
        res.end('File not found.');
      });
    }
  }

  createHandler(req, res, next) {
    if (!req.body || !req.body.length) {
      next(new _node.default.Error(_node.default.Error.FILE_SAVE_ERROR, 'Invalid file upload.'));
      return;
    }

    if (req.params.filename.length > 128) {
      next(new _node.default.Error(_node.default.Error.INVALID_FILE_NAME, 'Filename too long.'));
      return;
    }

    if (!req.params.filename.match(/^[_a-zA-Z0-9][a-zA-Z0-9@\.\ ~_-]*$/)) {
      next(new _node.default.Error(_node.default.Error.INVALID_FILE_NAME, 'Filename contains invalid characters.'));
      return;
    }

    const filename = req.params.filename;
    const contentType = req.get('Content-type');
    const config = req.config;
    const filesController = config.filesController;
    filesController.createFile(config, filename, req.body, contentType).then(result => {
      res.status(201);
      res.set('Location', result.url);
      res.json(result);
    }).catch(e => {
      _logger.default.error('Error creating a file: ', e);

      next(new _node.default.Error(_node.default.Error.FILE_SAVE_ERROR, `Could not store file: ${filename}.`));
    });
  }

  deleteHandler(req, res, next) {
    const filesController = req.config.filesController;
    filesController.deleteFile(req.config, req.params.filename).then(() => {
      res.status(200); // TODO: return useful JSON here?

      res.end();
    }).catch(() => {
      next(new _node.default.Error(_node.default.Error.FILE_DELETE_ERROR, 'Could not delete file.'));
    });
  }

}

exports.FilesRouter = FilesRouter;

function isFileStreamable(req, filesController) {
  return req.get('Range') && typeof filesController.adapter.handleFileStream === 'function';
}
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIi4uLy4uL3NyYy9Sb3V0ZXJzL0ZpbGVzUm91dGVyLmpzIl0sIm5hbWVzIjpbIkZpbGVzUm91dGVyIiwiZXhwcmVzc1JvdXRlciIsIm1heFVwbG9hZFNpemUiLCJyb3V0ZXIiLCJleHByZXNzIiwiUm91dGVyIiwiZ2V0IiwiZ2V0SGFuZGxlciIsInBvc3QiLCJyZXEiLCJyZXMiLCJuZXh0IiwiUGFyc2UiLCJFcnJvciIsIklOVkFMSURfRklMRV9OQU1FIiwiQm9keVBhcnNlciIsInJhdyIsInR5cGUiLCJsaW1pdCIsIk1pZGRsZXdhcmVzIiwiaGFuZGxlUGFyc2VIZWFkZXJzIiwiY3JlYXRlSGFuZGxlciIsImRlbGV0ZSIsImVuZm9yY2VNYXN0ZXJLZXlBY2Nlc3MiLCJkZWxldGVIYW5kbGVyIiwiY29uZmlnIiwiQ29uZmlnIiwicGFyYW1zIiwiYXBwSWQiLCJmaWxlc0NvbnRyb2xsZXIiLCJmaWxlbmFtZSIsImNvbnRlbnRUeXBlIiwibWltZSIsImdldFR5cGUiLCJpc0ZpbGVTdHJlYW1hYmxlIiwiaGFuZGxlRmlsZVN0cmVhbSIsImNhdGNoIiwic3RhdHVzIiwic2V0IiwiZW5kIiwiZ2V0RmlsZURhdGEiLCJ0aGVuIiwiZGF0YSIsImxlbmd0aCIsImJvZHkiLCJGSUxFX1NBVkVfRVJST1IiLCJtYXRjaCIsImNyZWF0ZUZpbGUiLCJyZXN1bHQiLCJ1cmwiLCJqc29uIiwiZSIsImxvZ2dlciIsImVycm9yIiwiZGVsZXRlRmlsZSIsIkZJTEVfREVMRVRFX0VSUk9SIiwiYWRhcHRlciJdLCJtYXBwaW5ncyI6Ijs7Ozs7OztBQUFBOztBQUNBOztBQUNBOztBQUNBOztBQUNBOztBQUNBOztBQUNBOzs7Ozs7OztBQUVPLE1BQU1BLFdBQU4sQ0FBa0I7QUFDdkJDLEVBQUFBLGFBQWEsQ0FBQztBQUFFQyxJQUFBQSxhQUFhLEdBQUc7QUFBbEIsTUFBNkIsRUFBOUIsRUFBa0M7QUFDN0MsUUFBSUMsTUFBTSxHQUFHQyxpQkFBUUMsTUFBUixFQUFiOztBQUNBRixJQUFB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UEgsQ0FPU2UsQ0FBQyxJQUFJO0FBQ1ZDLHNCQUFPQyxLQUFQLENBQWEseUJBQWIsRUFBd0NGLENBQXhDOztBQUNBeEMsTUFBQUEsSUFBSSxDQUNGLElBQUlDLGNBQU1DLEtBQVYsQ0FDRUQsY0FBTUMsS0FBTixDQUFZZ0MsZUFEZCxFQUVHLHlCQUF3QmYsUUFBUyxHQUZwQyxDQURFLENBQUo7QUFNRCxLQWZIO0FBZ0JEOztBQUVETixFQUFBQSxhQUFhLENBQUNmLEdBQUQsRUFBTUMsR0FBTixFQUFXQyxJQUFYLEVBQWlCO0FBQzVCLFVBQU1rQixlQUFlLEdBQUdwQixHQUFHLENBQUNnQixNQUFKLENBQVdJLGVBQW5DO0FBQ0FBLElBQUFBLGVBQWUsQ0FDWnlCLFVBREgsQ0FDYzdDLEdBQUcsQ0FBQ2dCLE1BRGxCLEVBQzBCaEIsR0FBRyxDQUFDa0IsTUFBSixDQUFXRyxRQURyQyxFQUVHVyxJQUZILENBRVEsTUFBTTtBQUNWL0IsTUFBQUEsR0FBRyxDQUFDMkIsTUFBSixDQUFXLEdBQVgsRUFEVSxDQUVWOztBQUNBM0IsTUFBQUEsR0FBRyxDQUFDNkIsR0FBSjtBQUNELEtBTkgsRUFPR0gsS0FQSCxDQU9TLE1BQU07QUFDWHpCLE1BQUFBLElBQUksQ0FDRixJQUFJQyxjQUFNQyxLQUFWLENBQ0VELGNBQU1DLEtBQU4sQ0FBWTBDLGlCQURkLEVBRUUsd0JBRkYsQ0FERSxDQUFKO0FBTUQsS0FkSDtBQWVEOztBQS9Ic0I7Ozs7QUFrSXpCLFNBQVNyQixnQkFBVCxDQUEwQnpCLEdBQTFCLEVBQStCb0IsZUFBL0IsRUFBZ0Q7QUFDOUMsU0FDRXBCLEdBQUcsQ0FBQ0gsR0FBSixDQUFRLE9BQVIsS0FDQSxPQUFPdUIsZUFBZSxDQUFDMkIsT0FBaEIsQ0FBd0JyQixnQkFBL0IsS0FBb0QsVUFGdEQ7QUFJRCIsInNvdXJjZXNDb250ZW50IjpbImltcG9ydCBleHByZXNzIGZyb20gJ2V4cHJlc3MnO1xuaW1wb3J0IEJvZHlQYXJzZXIgZnJvbSAnYm9keS1wYXJzZXInO1xuaW1wb3J0ICogYXMgTWlkZGxld2FyZXMgZnJvbSAnLi4vbWlkZGxld2FyZXMnO1xuaW1wb3J0IFBhcnNlIGZyb20gJ3BhcnNlL25vZGUnO1xuaW1wb3J0IENvbmZpZyBmcm9tICcuLi9Db25maWcnO1xuaW1wb3J0IG1pbWUgZnJvbSAnbWltZSc7XG5pbXBvcnQgbG9nZ2VyIGZyb20gJy4uL2xvZ2dlcic7XG5cbmV4cG9ydCBjbGFzcyBGaWxlc1JvdXRlciB7XG4gIGV4cHJlc3NSb3V0ZXIoeyBtYXhVcGxvYWRTaXplID0gJzIwTWInIH0gPSB7fSkge1xuICAgIHZhciByb3V0ZXIgPSBleHByZXNzLlJvdXRlcigpO1xuICAgIHJvdXRlci5nZXQoJy9maWxlcy86YXBwSWQvOmZpbGVuYW1lJywgdGhpcy5nZXRIYW5kbGVyKTtcblxuICAgIHJvdXRlci5wb3N0KCcvZmlsZXMnLCBmdW5jdGlvbihyZXEsIHJlcywgbmV4dCkge1xuICAgICAgbmV4dChcbiAgICAgICAgbmV3IFBhcnNlLkVycm9yKFBhcnNlLkVycm9yLklOVkFMSURfRklMRV9OQU1FLCAnRmlsZW5hbWUgbm90IHByb3ZpZGVkLicpXG4gICAgICApO1xuICAgIH0pO1xuXG4gICAgcm91dGVyLnBvc3QoXG4gICAgICAnL2ZpbGVzLzpmaWxlbmFtZScsXG4gICAgICBCb2R5UGFyc2VyLnJhdyh7XG4gICAgICAgIHR5cGU6ICgpID0+IHtcbiAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgfSxcbiAgICAgICAgbGltaXQ6IG1heFVwbG9hZFNpemUsXG4gICAgICB9KSwgLy8gQWxsb3cgdXBsb2FkcyB3aXRob3V0IENvbnRlbnQtVHlwZSwgb3Igd2l0aCBhbnkgQ29udGVudC1UeXBlLlxuICAgICAgTWlkZGxld2FyZXMuaGFuZGxlUGFyc2VIZWFkZXJzLFxuICAgICAgdGhpcy5jcmVhdGVIYW5kbGVyXG4gICAgKTtcblxuICAgIHJvdXRlci5kZWxldGUoXG4gICAgICAnL2ZpbGVzLzpmaWxlbmFtZScsXG4gICAgICBNaWRkbGV3YXJlcy5oYW5kbGVQYXJzZUhlYWRlcnMsXG4gICAgICBNaWRkbGV3YXJlcy5lbmZvcmNlTWFzdGVyS2V5QWNjZXNzLFxuICAgICAgdGhpcy5kZWxldGVIYW5kbGVyXG4gICAgKTtcbiAgICByZXR1cm4gcm91dGVyO1xuICB9XG5cbiAgZ2V0SGFuZGxlcihyZXEsIHJlcykge1xuICAgIGNvbnN0IGNvbmZpZyA9IENvbmZpZy5nZXQocmVxLnBhcmFtcy5hcHBJZCk7XG4gICAgY29uc3QgZmlsZXNDb250cm9sbGVyID0gY29uZmlnLmZpbGVzQ29udHJvbGxlcjtcbiAgICBjb25zdCBmaWxlbmFtZSA9IHJlcS5wYXJhbXMuZmlsZW5hbWU7XG4gICAgY29uc3QgY29udGVudFR5cGUgPSBtaW1lLmdldFR5cGUoZmlsZW5hbWUpO1xuICAgIGlmIChpc0ZpbGVTdHJlYW1hYmxlKHJlcSwgZmlsZXNDb250cm9sbGVyKSkge1xuICAgICAgZmlsZXNDb250cm9sbGVyXG4gICAgICAgIC5oYW5kbGVGaWxlU3RyZWFtKGNvbmZpZywgZmlsZW5hbWUsIHJlcSwgcmVzLCBjb250ZW50VHlwZSlcbiAgICAgICAgLmNhdGNoKCgpID0+IHtcbiAgICAgICAgICByZXMuc3RhdHVzKDQwNCk7XG4gICAgICAgICAgcmVzLnNldCgnQ29udGVudC1UeXBlJywgJ3RleHQvcGxhaW4nKTtcbiAgICAgICAgICByZXMuZW5kKCdGaWxlIG5vdCBmb3VuZC4nKTtcbiAgICAgICAgfSk7XG4gICAgfSBlbHNlIHtcbiAgICAgIGZpbGVzQ29udHJvbGxlclxuICAgICAgICAuZ2V0RmlsZURhdGEoY29uZmlnLCBmaWxlbmFtZSlcbiAgICAgICAgLnRoZW4oZGF0YSA9PiB7XG4gICAgICAgICAgcmVzLnN0YXR1cygyMDApO1xuICAgICAgICAgIHJlcy5zZXQoJ0NvbnRlbnQtVHlwZScsIGNvbnRlbnRUeXBlKTtcbiAgICAgICAgICByZXMuc2V0KCdDb250ZW50LUxlbmd0aCcsIGRhdGEubGVuZ3RoKTtcbiAgICAgICAgICByZXMuZW5kKGRhdGEpO1xuICAgICAgICB9KVxuICAgICAgICAuY2F0Y2goKCkgPT4ge1xuICAgICAgICAgIHJlcy5zdGF0dXMoNDA0KTtcbiAgICAgICAgICByZXMuc2V0KCdDb250ZW50LVR5cGUnLCAndGV4dC9wbGFpbicpO1xuICAgICAgICAgIHJlcy5lbmQoJ0ZpbGUgbm90IGZvdW5kLicpO1xuICAgICAgICB9KTtcbiAgICB9XG4gIH1cblxuICBjcmVhdGVIYW5kbGVyKHJlcSwgcmVzLCBuZXh0KSB7XG4gICAgaWYgKCFyZXEuYm9keSB8fCAhcmVxLmJvZHkubGVuZ3RoKSB7XG4gICAgICBuZXh0KFxuICAgICAgICBuZXcgUGFyc2UuRXJyb3IoUGFyc2UuRXJyb3IuRklMRV9TQVZFX0VSUk9SLCAnSW52YWxpZCBmaWxlIHVwbG9hZC4nKVxuICAgICAgKTtcbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICBpZiAocmVxLnBhcmFtcy5maWxlbmFtZS5sZW5ndGggPiAxMjgpIHtcbiAgICAgIG5leHQoXG4gICAgICAgIG5ldyBQYXJzZS5FcnJvcihQYXJzZS5FcnJvci5JTlZBTElEX0ZJTEVfTkFNRSwgJ0ZpbGVuYW1lIHRvbyBsb25nLicpXG4gICAgICApO1xuICAgICAgcmV0dXJuO1xuICAgIH1cblxuICAgIGlmICghcmVxLnBhcmFtcy5maWxlbmFtZS5tYXRjaCgvXltfYS16QS1aMC05XVthLXpBLVowLTlAXFwuXFwgfl8tXSokLykpIHtcbiAgICAgIG5leHQoXG4gICAgICAgIG5ldyBQYXJzZS5FcnJvcihcbiAgICAgICAgICBQYXJzZS5FcnJvci5JTlZBTElEX0ZJTEVfTkFNRSxcbiAgICAgICAgICAnRmlsZW5hbWUgY29udGFpbnMgaW52YWxpZCBjaGFyYWN0ZXJzLidcbiAgICAgICAgKVxuICAgICAgKTtcbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICBjb25zdCBmaWxlbmFtZSA9IHJlcS5wYXJhbXMuZmlsZW5hbWU7XG4gICAgY29uc3QgY29udGVudFR5cGUgPSByZXEuZ2V0KCdDb250ZW50LXR5cGUnKTtcbiAgICBjb25zdCBjb25maWcgPSByZXEuY29uZmlnO1xuICAgIGNvbnN0IGZpbGVzQ29udHJvbGxlciA9IGNvbmZpZy5maWxlc0NvbnRyb2xsZXI7XG5cbiAgICBmaWxlc0NvbnRyb2xsZXJcbiAgICAgIC5jcmVhdGVGaWxlKGNvbmZpZywgZmlsZW5hbWUsIHJlcS5ib2R5LCBjb250ZW50VHlwZSlcbiAgICAgIC50aGVuKHJlc3VsdCA9PiB7XG4gICAgICAgIHJlcy5zdGF0dXMoMjAxKTtcbiAgICAgICAgcmVzLnNldCgnTG9jYXRpb24nLCByZXN1bHQudXJsKTtcbiAgICAgICAgcmVzLmpzb24ocmVzdWx0KTtcbiAgICAgIH0pXG4gICAgICAuY2F0Y2goZSA9PiB7XG4gICAgICAgIGxvZ2dlci5lcnJvcignRXJyb3IgY3JlYXRpbmcgYSBmaWxlOiAnLCBlKTtcbiAgICAgICAgbmV4dChcbiAgICAgICAgICBuZXcgUGFyc2UuRXJyb3IoXG4gICAgICAgICAgICBQYXJzZS5FcnJvci5GSUxFX1NBVkVfRVJST1IsXG4gICAgICAgICAgICBgQ291bGQgbm90IHN0b3JlIGZpbGU6ICR7ZmlsZW5hbWV9LmBcbiAgICAgICAgICApXG4gICAgICAgICk7XG4gICAgICB9KTtcbiAgfVxuXG4gIGRlbGV0ZUhhbmRsZXIocmVxLCByZXMsIG5leHQpIHtcbiAgICBjb25zdCBmaWxlc0NvbnRyb2xsZXIgPSByZXEuY29uZmlnLmZpbGVzQ29udHJvbGxlcjtcbiAgICBmaWxlc0NvbnRyb2xsZXJcbiAgICAgIC5kZWxldGVGaWxlKHJlcS5jb25maWcsIHJlcS5wYXJhbXMuZmlsZW5hbWUpXG4gICAgICAudGhlbigoKSA9PiB7XG4gICAgICAgIHJlcy5zdGF0dXMoMjAwKTtcbiAgICAgICAgLy8gVE9ETzogcmV0dXJuIHVzZWZ1bCBKU09OIGhlcmU/XG4gICAgICAgIHJlcy5lbmQoKTtcbiAgICAgIH0pXG4gICAgICAuY2F0Y2goKCkgPT4ge1xuICAgICAgICBuZXh0KFxuICAgICAgICAgIG5ldyBQYXJzZS5FcnJvcihcbiAgICAgICAgICAgIFBhcnNlLkVycm9yLkZJTEVfREVMRVRFX0VSUk9SLFxuICAgICAgICAgICAgJ0NvdWxkIG5vdCBkZWxldGUgZmlsZS4nXG4gICAgICAgICAgKVxuICAgICAgICApO1xuICAgICAgfSk7XG4gIH1cbn1cblxuZnVuY3Rpb24gaXNGaWxlU3RyZWFtYWJsZShyZXEsIGZpbGVzQ29udHJvbGxlcikge1xuICByZXR1cm4gKFxuICAgIHJlcS5nZXQoJ1JhbmdlJykgJiZcbiAgICB0eXBlb2YgZmlsZXNDb250cm9sbGVyLmFkYXB0ZXIuaGFuZGxlRmlsZVN0cmVhbSA9PT0gJ2Z1bmN0aW9uJ1xuICApO1xufVxuIl19