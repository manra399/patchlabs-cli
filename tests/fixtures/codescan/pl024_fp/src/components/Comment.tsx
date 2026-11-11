import DOMPurify from "dompurify";
export function Comment({ comment }) {
  return <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(comment.body) }} />;
}
