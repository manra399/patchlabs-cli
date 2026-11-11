export default function Pro({ session }) {
  const { is_pro } = session.user.user_metadata;
  return is_pro ? <ProTools /> : <Upsell />;
}
