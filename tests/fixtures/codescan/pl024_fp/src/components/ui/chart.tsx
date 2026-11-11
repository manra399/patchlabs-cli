const ChartStyle = ({ id, config }) => {
  return (
    <style
      dangerouslySetInnerHTML={{
        __html: Object.entries(THEMES).map(([theme, prefix]) => `${prefix} [data-chart=${id}] {}`).join("\n"),
      }}
    />
  );
};
