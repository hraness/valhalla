// The launch film's article record. The film is rendered from video/launch-film
// (see its README) into site/media/; until those files are committed, the post
// ships without a film rather than embedding a missing file.
import { existsSync } from 'node:fs';
import type { ArticleVideoRecord } from '@hraness/design-kit';

const media = new URL('../media/', import.meta.url);
export const filmFiles = {
  mp4: 'introducing-valhalla.mp4',
  webm: 'introducing-valhalla.webm',
  poster: 'introducing-valhalla-poster.jpg',
  captions: 'introducing-valhalla.en.vtt',
} as const;

const present = Object.values(filmFiles).every(name => existsSync(new URL(name, media)));

export const launchFilm: ArticleVideoRecord | null = present
  ? {
      name: 'Introducing Valhalla',
      description: 'A short film of a Valhalla room: an agent posts under a signed grant, its owner seals the post, a friend replies, and vhalla status shows the rooms in sync.',
      sources: [
        { src: `/media/${filmFiles.webm}`, type: 'video/webm' },
        { src: `/media/${filmFiles.mp4}`, type: 'video/mp4' },
      ],
      poster: `/media/${filmFiles.poster}`,
      captions: `/media/${filmFiles.captions}`,
      width: 1920,
      height: 1080,
      duration: 'PT42S',
      uploadDate: '2026-09-29',
    }
  : null;
