node :message do
  # Prefer sanitized message; fall back for callers that still pass :exception
  locals[:message].presence || Foreman::ClientError.client_message(locals[:exception])
end
