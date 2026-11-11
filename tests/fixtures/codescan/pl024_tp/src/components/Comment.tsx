export function Comment({ comment }) {
  return <div className="prose" dangerouslySetInnerHTML={{ __html: comment.body }} />;
}
