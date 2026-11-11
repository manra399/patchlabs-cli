import { marked } from "marked";
export function Post({ post }) {
  return (
    <article
      dangerouslySetInnerHTML={{
        __html: marked(post.content),
      }}
    />
  );
}
