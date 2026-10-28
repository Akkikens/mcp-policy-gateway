// Example gateway policy. Principals are User::"<sub>" with parents
// Group::"<SCIM group>". Resources are Tool::"<server>/<tool>" with parent
// Server::"<server>". Actions: list_tool (projection into tools/list) and
// call_tool (context.args = call arguments, context.scopes = token scopes).
//
// A tool is callable only if it is also listable, so write both.
// Guard optional arguments with `has`: an evaluation error denies the call.

@id("eng-list-files")
permit (
  principal in Group::"engineering",
  action == Action::"list_tool",
  resource == Tool::"files/read_file"
);

@id("eng-read-docs-only")
permit (
  principal in Group::"engineering",
  action == Action::"call_tool",
  resource == Tool::"files/read_file"
)
when {
  context.args has path &&
  context.args.path like "/srv/docs/*" &&
  !(context.args.path like "*..*")
};

@id("admins-everything")
permit (principal in Group::"admins", action, resource);

@id("everyone-list-search")
permit (principal, action == Action::"list_tool", resource == Tool::"web/search_web");

@id("search-needs-scope")
permit (principal, action == Action::"call_tool", resource == Tool::"web/search_web")
when { context.scopes.contains("web:search") };

@id("eng-email-internal")
permit (
  principal in Group::"engineering",
  action in [Action::"list_tool", Action::"call_tool"],
  resource == Tool::"web/send_email"
)
when {
  action == Action::"list_tool" ||
  (context has args && context.args has to && context.args.to like "*@example.com")
};

// Even admins may not write outside the workspace.
@id("no-writes-outside-workspace")
forbid (principal, action == Action::"call_tool", resource == Tool::"files/write_file")
unless { context has args && context.args has path && context.args.path like "/srv/workspace/*" && !(context.args.path like "*..*") };
