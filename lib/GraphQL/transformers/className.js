"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.transformClassNameToGraphQL = void 0;

const transformClassNameToGraphQL = className => {
  if (className[0] === '_') {
    className = className.slice(1);
  }

  return className[0].toUpperCase() + className.slice(1);
};

exports.transformClassNameToGraphQL = transformClassNameToGraphQL;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIi4uLy4uLy4uL3NyYy9HcmFwaFFML3RyYW5zZm9ybWVycy9jbGFzc05hbWUuanMiXSwibmFtZXMiOlsidHJhbnNmb3JtQ2xhc3NOYW1lVG9HcmFwaFFMIiwiY2xhc3NOYW1lIiwic2xpY2UiLCJ0b1VwcGVyQ2FzZSJdLCJtYXBwaW5ncyI6Ijs7Ozs7OztBQUFBLE1BQU1BLDJCQUEyQixHQUFHQyxTQUFTLElBQUk7QUFDL0MsTUFBSUEsU0FBUyxDQUFDLENBQUQsQ0FBVCxLQUFpQixHQUFyQixFQUEwQjtBQUN4QkEsSUFBQUEsU0FBUyxHQUFHQSxTQUFTLENBQUNDLEtBQVYsQ0FBZ0IsQ0FBaEIsQ0FBWjtBQUNEOztBQUNELFNBQU9ELFNBQVMsQ0FBQyxDQUFELENBQVQsQ0FBYUUsV0FBYixLQUE2QkYsU0FBUyxDQUFDQyxLQUFWLENBQWdCLENBQWhCLENBQXBDO0FBQ0QsQ0FMRCIsInNvdXJjZXNDb250ZW50IjpbImNvbnN0IHRyYW5zZm9ybUNsYXNzTmFtZVRvR3JhcGhRTCA9IGNsYXNzTmFtZSA9PiB7XG4gIGlmIChjbGFzc05hbWVbMF0gPT09ICdfJykge1xuICAgIGNsYXNzTmFtZSA9IGNsYXNzTmFtZS5zbGljZSgxKTtcbiAgfVxuICByZXR1cm4gY2xhc3NOYW1lWzBdLnRvVXBwZXJDYXNlKCkgKyBjbGFzc05hbWUuc2xpY2UoMSk7XG59O1xuXG5leHBvcnQgeyB0cmFuc2Zvcm1DbGFzc05hbWVUb0dyYXBoUUwgfTtcbiJdfQ==