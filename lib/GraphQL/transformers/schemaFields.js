"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.transformToGraphQL = exports.transformToParse = void 0;

var _node = _interopRequireDefault(require("parse/node"));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function ownKeys(object, enumerableOnly) { var keys = Object.keys(object); if (Object.getOwnPropertySymbols) { var symbols = Object.getOwnPropertySymbols(object); if (enumerableOnly) symbols = symbols.filter(function (sym) { return Object.getOwnPropertyDescriptor(object, sym).enumerable; }); keys.push.apply(keys, symbols); } return keys; }

function _objectSpread(target) { for (var i = 1; i < arguments.length; i++) { var source = arguments[i] != null ? arguments[i] : {}; if (i % 2) { ownKeys(source, true).forEach(function (key) { _defineProperty(target, key, source[key]); }); } else if (Object.getOwnPropertyDescriptors) { Object.defineProperties(target, Object.getOwnPropertyDescriptors(source)); } else { ownKeys(source).forEach(function (key) { Object.defineProperty(target, key, Object.getOwnPropertyDescriptor(source, key)); }); } } return target; }

function _defineProperty(obj, key, value) { if (key in obj) { Object.defineProperty(obj, key, { value: value, enumerable: true, configurable: true, writable: true }); } else { obj[key] = value; } return obj; }

const transformToParse = (graphQLSchemaFields, existingFields) => {
  if (!graphQLSchemaFields) {
    return {};
  }

  let parseSchemaFields = {};

  const reducerGenerator = type => (parseSchemaFields, field) => {
    if (type === 'Remove') {
      if (existingFields[field.name]) {
        return _objectSpread({}, parseSchemaFields, {
          [field.name]: {
            __op: 'Delete'
          }
        });
      } else {
        return parseSchemaFields;
      }
    }

    if (graphQLSchemaFields.remove && graphQLSchemaFields.remove.find(removeField => removeField.name === field.name)) {
      return parseSchemaFields;
    }

    if (parseSchemaFields[field.name] || existingFields && existingFields[field.name]) {
      throw new _node.default.Error(_node.default.Error.INVALID_KEY_NAME, `Duplicated field name: ${field.name}`);
    }

    if (type === 'Relation' || type === 'Pointer') {
      return _objectSpread({}, parseSchemaFields, {
        [field.name]: {
          type,
          targetClass: field.targetClassName
        }
      });
    }

    return _objectSpread({}, parseSchemaFields, {
      [field.name]: {
        type
      }
    });
  };

  if (graphQLSchemaFields.addStrings) {
    parseSchemaFields = graphQLSchemaFields.addStrings.reduce(reducerGenerator('String'), parseSchemaFields);
  }

  if (graphQLSchemaFields.addNumbers) {
    parseSchemaFields = graphQLSchemaFields.addNumbers.reduce(reducerGenerator('Number'), parseSchemaFields);
  }

  if (graphQLSchemaFields.addBooleans) {
    parseSchemaFields = graphQLSchemaFields.addBooleans.reduce(reducerGenerator('Boolean'), parseSchemaFields);
  }

  if (graphQLSchemaFields.addArrays) {
    parseSchemaFields = graphQLSchemaFields.addArrays.reduce(reducerGenerator('Array'), parseSchemaFields);
  }

  if (graphQLSchemaFields.addObjects) {
    parseSchemaFields = graphQLSchemaFields.addObjects.reduce(reducerGenerator('Object'), parseSchemaFields);
  }

  if (graphQLSchemaFields.addDates) {
    parseSchemaFields = graphQLSchemaFields.addDates.reduce(reducerGenerator('Date'), parseSchemaFields);
  }

  if (graphQLSchemaFields.addFiles) {
    parseSchemaFields = graphQLSchemaFields.addFiles.reduce(reducerGenerator('File'), parseSchemaFields);
  }

  if (graphQLSchemaFields.addGeoPoint) {
    parseSchemaFields = [graphQLSchemaFields.addGeoPoint].reduce(reducerGenerator('GeoPoint'), parseSchemaFields);
  }

  if (graphQLSchemaFields.addPolygons) {
    parseSchemaFields = graphQLSchemaFields.addPolygons.reduce(reducerGenerator('Polygon'), parseSchemaFields);
  }

  if (graphQLSchemaFields.addBytes) {
    parseSchemaFields = graphQLSchemaFields.addBytes.reduce(reducerGenerator('Bytes'), parseSchemaFields);
  }

  if (graphQLSchemaFields.addPointers) {
    parseSchemaFields = graphQLSchemaFields.addPointers.reduce(reducerGenerator('Pointer'), parseSchemaFields);
  }

  if (graphQLSchemaFields.addRelations) {
    parseSchemaFields = graphQLSchemaFields.addRelations.reduce(reducerGenerator('Relation'), parseSchemaFields);
  }

  if (existingFields && graphQLSchemaFields.remove) {
    parseSchemaFields = graphQLSchemaFields.remove.reduce(reducerGenerator('Remove'), parseSchemaFields);
  }

  return parseSchemaFields;
};

exports.transformToParse = transformToParse;

const transformToGraphQL = parseSchemaFields => {
  return Object.keys(parseSchemaFields).map(name => ({
    name,
    type: parseSchemaFields[name].type,
    targetClassName: parseSchemaFields[name].targetClass
  }));
};

exports.transformToGraphQL = transformToGraphQL;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIi4uLy4uLy4uL3NyYy9HcmFwaFFML3RyYW5zZm9ybWVycy9zY2hlbWFGaWVsZHMuanMiXSwibmFtZXMiOlsidHJhbnNmb3JtVG9QYXJzZSIsImdyYXBoUUxTY2hlbWFGaWVsZHMiLCJleGlzdGluZ0ZpZWxkcyIsInBhcnNlU2NoZW1hRmllbGRzIiwicmVkdWNlckdlbmVyYXRvciIsInR5cGUiLCJmaWVsZCIsIm5hbWUiLCJfX29wIiwicmVtb3ZlIiwiZmluZCIsInJlbW92ZUZpZWxkIiwiUGFyc2UiLCJFcnJvciIsIklOVkFMSURfS0VZX05BTUUiLCJ0YXJnZXRDbGFzcyIsInRhcmdldENsYXNzTmFtZSIsImFkZFN0cmluZ3MiLCJyZWR1Y2UiLCJhZGROdW1iZXJzIiwiYWRkQm9vbGVhbnMiLCJhZGRBcnJheXMiLCJhZGRPYmplY3RzIiwiYWRkRGF0ZXMiLCJhZGRGaWxlcyIsImFkZEdlb1BvaW50IiwiYWRkUG9seWdvbnMiLCJhZGRCeXRlcyIsImFkZFBvaW50ZXJzIiwiYWRkUmVsYXRpb25zIiwidHJhbnNmb3JtVG9HcmFwaFFMIiwiT2JqZWN0Iiwia2V5cyIsIm1hcCJdLCJtYXBwaW5ncyI6Ijs7Ozs7OztBQUFBOzs7Ozs7Ozs7O0FBRUEsTUFBTUEsZ0JBQWdCLEdBQUcsQ0FBQ0MsbUJBQUQsRUFBc0JDLGNBQXRCLEtBQXlDO0FBQ2hFLE1BQUksQ0FBQ0QsbUJBQUwsRUFBMEI7QUFDeEIsV0FBTyxFQUFQO0FBQ0Q7O0FBRUQsTUFBSUUsaUJBQWlCLEdBQUcsRUFBeEI7O0FBRUEsUUFBTUMsZ0JBQWdCLEdBQUdDLElBQUksSUFBSSxDQUFDRixpQkFBRCxFQUFvQkcsS0FBcEIsS0FBOEI7QUFDN0QsUUFBSUQsSUFBSSxLQUFLLFFBQWIsRUFBdUI7QUFDckIsVUFBSUgsY0FBYyxDQUFDSSxLQUFLLENBQUNDLElBQVAsQ0FBbEIsRUFBZ0M7QUFDOUIsaUNBQ0tKLGlCQURMO0FBRUUsV0FBQ0csS0FBSyxDQUFDQyxJQUFQLEdBQWM7QUFDWkMsWUFBQUEsSUFB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O0FBd0lBLE1BQU0yQixrQkFBa0IsR0FBRzNCLGlCQUFpQixJQUFJO0FBQzlDLFNBQU80QixNQUFNLENBQUNDLElBQVAsQ0FBWTdCLGlCQUFaLEVBQStCOEIsR0FBL0IsQ0FBbUMxQixJQUFJLEtBQUs7QUFDakRBLElBQUFBLElBRGlEO0FBRWpERixJQUFBQSxJQUFJLEVBQUVGLGlCQUFpQixDQUFDSSxJQUFELENBQWpCLENBQXdCRixJQUZtQjtBQUdqRFcsSUFBQUEsZUFBZSxFQUFFYixpQkFBaUIsQ0FBQ0ksSUFBRCxDQUFqQixDQUF3QlE7QUFIUSxHQUFMLENBQXZDLENBQVA7QUFLRCxDQU5EIiwic291cmNlc0NvbnRlbnQiOlsiaW1wb3J0IFBhcnNlIGZyb20gJ3BhcnNlL25vZGUnO1xuXG5jb25zdCB0cmFuc2Zvcm1Ub1BhcnNlID0gKGdyYXBoUUxTY2hlbWFGaWVsZHMsIGV4aXN0aW5nRmllbGRzKSA9PiB7XG4gIGlmICghZ3JhcGhRTFNjaGVtYUZpZWxkcykge1xuICAgIHJldHVybiB7fTtcbiAgfVxuXG4gIGxldCBwYXJzZVNjaGVtYUZpZWxkcyA9IHt9O1xuXG4gIGNvbnN0IHJlZHVjZXJHZW5lcmF0b3IgPSB0eXBlID0+IChwYXJzZVNjaGVtYUZpZWxkcywgZmllbGQpID0+IHtcbiAgICBpZiAodHlwZSA9PT0gJ1JlbW92ZScpIHtcbiAgICAgIGlmIChleGlzdGluZ0ZpZWxkc1tmaWVsZC5uYW1lXSkge1xuICAgICAgICByZXR1cm4ge1xuICAgICAgICAgIC4uLnBhcnNlU2NoZW1hRmllbGRzLFxuICAgICAgICAgIFtmaWVsZC5uYW1lXToge1xuICAgICAgICAgICAgX19vcDogJ0RlbGV0ZScsXG4gICAgICAgICAgfSxcbiAgICAgICAgfTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIHJldHVybiBwYXJzZVNjaGVtYUZpZWxkcztcbiAgICAgIH1cbiAgICB9XG4gICAgaWYgKFxuICAgICAgZ3JhcGhRTFNjaGVtYUZpZWxkcy5yZW1vdmUgJiZcbiAgICAgIGdyYXBoUUxTY2hlbWFGaWVsZHMucmVtb3ZlLmZpbmQoXG4gICAgICAgIHJlbW92ZUZpZWxkID0+IHJlbW92ZUZpZWxkLm5hbWUgPT09IGZpZWxkLm5hbWVcbiAgICAgIClcbiAgICApIHtcbiAgICAgIHJldHVybiBwYXJzZVNjaGVtYUZpZWxkcztcbiAgICB9XG4gICAgaWYgKFxuICAgICAgcGFyc2VTY2hlbWFGaWVsZHNbZmllbGQubmFtZV0gfHxcbiAgICAgIChleGlzdGluZ0ZpZWxkcyAmJiBleGlzdGluZ0ZpZWxkc1tmaWVsZC5uYW1lXSlcbiAgICApIHtcbiAgICAgIHRocm93IG5ldyBQYXJzZS5FcnJvcihcbiAgICAgICAgUGFyc2UuRXJyb3IuSU5WQUxJRF9LRVlfTkFNRSxcbiAgICAgICAgYER1cGxpY2F0ZWQgZmllbGQgbmFtZTogJHtmaWVsZC5uYW1lfWBcbiAgICAgICk7XG4gICAgfVxuICAgIGlmICh0eXBlID09PSAnUmVsYXRpb24nIHx8IHR5cGUgPT09ICdQb2ludGVyJykge1xuICAgICAgcmV0dXJuIHtcbiAgICAgICAgLi4ucGFyc2VTY2hlbWFGaWVsZHMsXG4gICAgICAgIFtmaWVsZC5uYW1lXToge1xuICAgICAgICAgIHR5cGUsXG4gICAgICAgICAgdGFyZ2V0Q2xhc3M6IGZpZWxkLnRhcmdldENsYXNzTmFtZSxcbiAgICAgICAgfSxcbiAgICAgIH07XG4gICAgfVxuICAgIHJldHVybiB7XG4gICAgICAuLi5wYXJzZVNjaGVtYUZpZWxkcyxcbiAgICAgIFtmaWVsZC5uYW1lXToge1xuICAgICAgICB0eXBlLFxuICAgICAgfSxcbiAgICB9O1xuICB9O1xuXG4gIGlmIChncmFwaFFMU2NoZW1hRmllbGRzLmFkZFN0cmluZ3MpIHtcbiAgICBwYXJzZVNjaGVtYUZpZWxkcyA9IGdyYXBoUUxTY2hlbWFGaWVsZHMuYWRkU3RyaW5ncy5yZWR1Y2UoXG4gICAgICByZWR1Y2VyR2VuZXJhdG9yKCdTdHJpbmcnKSxcbiAgICAgIHBhcnNlU2NoZW1hRmllbGRzXG4gICAgKTtcbiAgfVxuICBpZiAoZ3JhcGhRTFNjaGVtYUZpZWxkcy5hZGROdW1iZXJzKSB7XG4gICAgcGFyc2VTY2hlbWFGaWVsZHMgPSBncmFwaFFMU2NoZW1hRmllbGRzLmFkZE51bWJlcnMucmVkdWNlKFxuICAgICAgcmVkdWNlckdlbmVyYXRvcignTnVtYmVyJyksXG4gICAgICBwYXJzZVNjaGVtYUZpZWxkc1xuICAgICk7XG4gIH1cbiAgaWYgKGdyYXBoUUxTY2hlbWFGaWVsZHMuYWRkQm9vbGVhbnMpIHtcbiAgICBwYXJzZVNjaGVtYUZpZWxkcyA9IGdyYXBoUUxTY2hlbWFGaWVsZHMuYWRkQm9vbGVhbnMucmVkdWNlKFxuICAgICAgcmVkdWNlckdlbmVyYXRvcignQm9vbGVhbicpLFxuICAgICAgcGFyc2VTY2hlbWFGaWVsZHNcbiAgICApO1xuICB9XG4gIGlmIChncmFwaFFMU2NoZW1hRmllbGRzLmFkZEFycmF5cykge1xuICAgIHBhcnNlU2NoZW1hRmllbGRzID0gZ3JhcGhRTFNjaGVtYUZpZWxkcy5hZGRBcnJheXMucmVkdWNlKFxuICAgICAgcmVkdWNlckdlbmVyYXRvcignQXJyYXknKSxcbiAgICAgIHBhcnNlU2NoZW1hRmllbGRzXG4gICAgKTtcbiAgfVxuICBpZiAoZ3JhcGhRTFNjaGVtYUZpZWxkcy5hZGRPYmplY3RzKSB7XG4gICAgcGFyc2VTY2hlbWFGaWVsZHMgPSBncmFwaFFMU2NoZW1hRmllbGRzLmFkZE9iamVjdHMucmVkdWNlKFxuICAgICAgcmVkdWNlckdlbmVyYXRvcignT2JqZWN0JyksXG4gICAgICBwYXJzZVNjaGVtYUZpZWxkc1xuICAgICk7XG4gIH1cbiAgaWYgKGdyYXBoUUxTY2hlbWFGaWVsZHMuYWRkRGF0ZXMpIHtcbiAgICBwYXJzZVNjaGVtYUZpZWxkcyA9IGdyYXBoUUxTY2hlbWFGaWVsZHMuYWRkRGF0ZXMucmVkdWNlKFxuICAgICAgcmVkdWNlckdlbmVyYXRvcignRGF0ZScpLFxuICAgICAgcGFyc2VTY2hlbWFGaWVsZHNcbiAgICApO1xuICB9XG4gIGlmIChncmFwaFFMU2NoZW1hRmllbGRzLmFkZEZpbGVzKSB7XG4gICAgcGFyc2VTY2hlbWFGaWVsZHMgPSBncmFwaFFMU2NoZW1hRmllbGRzLmFkZEZpbGVzLnJlZHVjZShcbiAgICAgIHJlZHVjZXJHZW5lcmF0b3IoJ0ZpbGUnKSxcbiAgICAgIHBhcnNlU2NoZW1hRmllbGRzXG4gICAgKTtcbiAgfVxuICBpZiAoZ3JhcGhRTFNjaGVtYUZpZWxkcy5hZGRHZW9Qb2ludCkge1xuICAgIHBhcnNlU2NoZW1hRmllbGRzID0gW2dyYXBoUUxTY2hlbWFGaWVsZHMuYWRkR2VvUG9pbnRdLnJlZHVjZShcbiAgICAgIHJlZHVjZXJHZW5lcmF0b3IoJ0dlb1BvaW50JyksXG4gICAgICBwYXJzZVNjaGVtYUZpZWxkc1xuICAgICk7XG4gIH1cbiAgaWYgKGdyYXBoUUxTY2hlbWFGaWVsZHMuYWRkUG9seWdvbnMpIHtcbiAgICBwYXJzZVNjaGVtYUZpZWxkcyA9IGdyYXBoUUxTY2hlbWFGaWVsZHMuYWRkUG9seWdvbnMucmVkdWNlKFxuICAgICAgcmVkdWNlckdlbmVyYXRvcignUG9seWdvbicpLFxuICAgICAgcGFyc2VTY2hlbWFGaWVsZHNcbiAgICApO1xuICB9XG4gIGlmIChncmFwaFFMU2NoZW1hRmllbGRzLmFkZEJ5dGVzKSB7XG4gICAgcGFyc2VTY2hlbWFGaWVsZHMgPSBncmFwaFFMU2NoZW1hRmllbGRzLmFkZEJ5dGVzLnJlZHVjZShcbiAgICAgIHJlZHVjZXJHZW5lcmF0b3IoJ0J5dGVzJyksXG4gICAgICBwYXJzZVNjaGVtYUZpZWxkc1xuICAgICk7XG4gIH1cbiAgaWYgKGdyYXBoUUxTY2hlbWFGaWVsZHMuYWRkUG9pbnRlcnMpIHtcbiAgICBwYXJzZVNjaGVtYUZpZWxkcyA9IGdyYXBoUUxTY2hlbWFGaWVsZHMuYWRkUG9pbnRlcnMucmVkdWNlKFxuICAgICAgcmVkdWNlckdlbmVyYXRvcignUG9pbnRlcicpLFxuICAgICAgcGFyc2VTY2hlbWFGaWVsZHNcbiAgICApO1xuICB9XG4gIGlmIChncmFwaFFMU2NoZW1hRmllbGRzLmFkZFJlbGF0aW9ucykge1xuICAgIHBhcnNlU2NoZW1hRmllbGRzID0gZ3JhcGhRTFNjaGVtYUZpZWxkcy5hZGRSZWxhdGlvbnMucmVkdWNlKFxuICAgICAgcmVkdWNlckdlbmVyYXRvcignUmVsYXRpb24nKSxcbiAgICAgIHBhcnNlU2NoZW1hRmllbGRzXG4gICAgKTtcbiAgfVxuICBpZiAoZXhpc3RpbmdGaWVsZHMgJiYgZ3JhcGhRTFNjaGVtYUZpZWxkcy5yZW1vdmUpIHtcbiAgICBwYXJzZVNjaGVtYUZpZWxkcyA9IGdyYXBoUUxTY2hlbWFGaWVsZHMucmVtb3ZlLnJlZHVjZShcbiAgICAgIHJlZHVjZXJHZW5lcmF0b3IoJ1JlbW92ZScpLFxuICAgICAgcGFyc2VTY2hlbWFGaWVsZHNcbiAgICApO1xuICB9XG5cbiAgcmV0dXJuIHBhcnNlU2NoZW1hRmllbGRzO1xufTtcblxuY29uc3QgdHJhbnNmb3JtVG9HcmFwaFFMID0gcGFyc2VTY2hlbWFGaWVsZHMgPT4ge1xuICByZXR1cm4gT2JqZWN0LmtleXMocGFyc2VTY2hlbWFGaWVsZHMpLm1hcChuYW1lID0+ICh7XG4gICAgbmFtZSxcbiAgICB0eXBlOiBwYXJzZVNjaGVtYUZpZWxkc1tuYW1lXS50eXBlLFxuICAgIHRhcmdldENsYXNzTmFtZTogcGFyc2VTY2hlbWFGaWVsZHNbbmFtZV0udGFyZ2V0Q2xhc3MsXG4gIH0pKTtcbn07XG5cbmV4cG9ydCB7IHRyYW5zZm9ybVRvUGFyc2UsIHRyYW5zZm9ybVRvR3JhcGhRTCB9O1xuIl19