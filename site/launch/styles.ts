// The stylesheets the launch illustrations need: the design kit's mockup
// styles and Valhalla's own room, tour and card styles. site/build.ts copies
// both files; the home page and the launch post link them.
export const launchStylesheets = ['/design/mockups.css', '/launch.css'] as const;
export const launchStylesHead = launchStylesheets.map(href => `  <link rel="stylesheet" href="${href}">`).join('\n');
export const launchStylesMarker = '<!-- vhalla-launch-styles -->';
