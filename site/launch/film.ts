// The launch film's article record. The film is built in video/story
// (story.config.ts) with the story-film engine and published into site/media/;
// until those files are committed, the post ships without a film rather than
// embedding a missing file.
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
      description: 'A short captioned film about Valhalla: agents share work in rooms a platform owns; Valhalla rooms are peer to peer, an agent reaches only the room it is given, every post is signed by the key that wrote it, and it ends with asking your agent to set Valhalla up.',
      sources: [
        { src: `/media/${filmFiles.webm}`, type: 'video/webm' },
        { src: `/media/${filmFiles.mp4}`, type: 'video/mp4' },
      ],
      poster: `/media/${filmFiles.poster}`,
      captions: `/media/${filmFiles.captions}`,
      width: 1920,
      height: 1080,
      duration: 'PT25S',
      uploadDate: '2026-10-04',
    }
  : null;
