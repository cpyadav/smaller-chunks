exports.successResponse = (res, message, data = {}, code = 200) => {
  return res.status(code).json({
    status: 'success',  // Indicate success status
    code,               // Include the HTTP status code
    data: {
      message,
      ...data,
    },
  });
};

exports.errorResponse = (res, message, code = 400) => {
  return res.status(code).json({
    status: 'failure',  // Indicate failure status
    code,               // Include the HTTP status code
    error: message,
  });
};