# Component patterns

Copy-paste-quality starting points. Each is a complete, senior-grade implementation. Modify for the actual project, but don't water them down.

## UI primitives (`src/components/ui/`)

### `Container.astro` — max-width wrapper

```astro
---
interface Props {
  as?: 'div' | 'section' | 'article' | 'header' | 'footer' | 'main';
  class?: string;
}
const { as: Tag = 'div', class: className } = Astro.props;
---
<Tag class:list={['mx-auto w-full max-w-7xl px-4 sm:px-6 lg:px-8', className]}>
  <slot />
</Tag>
```

Polymorphic `as` prop with a sensible default. Always handle `class` passthrough.

### `Section.astro` — vertical-rhythm wrapper around `Container`

```astro
---
import Container from './Container.astro';

interface Props {
  id?: string;
  class?: string;
  containerClass?: string;
  spacing?: 'sm' | 'md' | 'lg';
}
const { id, class: className, containerClass, spacing = 'md' } = Astro.props;

const spacings = {
  sm: 'py-12 sm:py-16',
  md: 'py-16 sm:py-24',
  lg: 'py-24 sm:py-32',
} as const;
---
<section id={id} class:list={[spacings[spacing], className]}>
  <Container class={containerClass}>
    <slot />
  </Container>
</section>
```

### `Button.astro` — variants via lookup, polymorphic `<button>` / `<a>`

```astro
---
interface Props {
  variant?: 'primary' | 'secondary' | 'ghost';
  size?: 'sm' | 'md' | 'lg';
  href?: string;
  type?: 'button' | 'submit' | 'reset';
  class?: string;
}
const {
  variant = 'primary',
  size = 'md',
  href,
  type = 'button',
  class: className,
} = Astro.props;

const base =
  'inline-flex items-center justify-center gap-2 rounded-lg font-medium transition ' +
  'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent-500 focus-visible:ring-offset-2 ' +
  'disabled:opacity-50 disabled:pointer-events-none';

const variants = {
  primary:   'bg-accent-500 text-white hover:bg-accent-600',
  secondary: 'bg-gray-100 text-gray-900 hover:bg-gray-200',
  ghost:     'bg-transparent text-accent-600 hover:bg-accent-50',
} as const;

const sizes = {
  sm: 'px-3 py-1.5 text-sm',
  md: 'px-4 py-2 text-base',
  lg: 'px-6 py-3 text-lg',
} as const;

const classes = [base, variants[variant], sizes[size], className];
---
{href ? (
  <a href={href} class:list={classes}><slot /></a>
) : (
  <button type={type} class:list={classes}><slot /></button>
)}
```

Critical bits: `focus-visible` ring (a11y), polymorphic to `<a>` when `href` is given, lookup tables for variants/sizes.

### `Card.astro` — feature/testimonial card

```astro
---
interface Props {
  class?: string;
}
const { class: className } = Astro.props;
---
<div class:list={[
  'rounded-2xl border border-gray-200 bg-white p-6 sm:p-8',
  'shadow-sm hover:shadow-md transition-shadow',
  className,
]}>
  <slot />
</div>
```

Intentionally minimal. The card composes; it doesn't impose layout on its content.

## Sections (`src/components/sections/`)

### `Hero.astro` — full example

```astro
---
import { getEntry } from 'astro:content';
import Container from '../ui/Container.astro';
import Button from '../ui/Button.astro';

const settings = await getEntry('site', 'settings');
if (!settings) throw new Error('Site settings missing');
const { name, tagline, description, cta } = settings.data;
---
<header class="relative overflow-hidden bg-gradient-to-b from-accent-50 to-white pt-24 pb-16 sm:pt-32 sm:pb-24">
  <Container>
    <div class="mx-auto max-w-3xl text-center">
      <h1 class="text-4xl font-bold tracking-tight text-gray-900 sm:text-6xl">
        {tagline}
      </h1>
      <p class="mt-6 text-lg leading-8 text-gray-600 sm:text-xl">
        {description}
      </p>
      <div class="mt-10 flex items-center justify-center gap-4">
        <Button variant="primary" size="lg" href={cta.href}>
          {cta.label}
        </Button>
        <Button variant="ghost" size="lg" href="#features">
          Learn more
        </Button>
      </div>
    </div>
  </Container>
</header>
```

Note: `<h1>` on the hero only. Other sections use `<h2>`. The hero is a `<header>`, not a `<section>` — it's the page header.

### `Features.astro`

```astro
---
import { getCollection } from 'astro:content';
import Section from '../ui/Section.astro';
import Card from '../ui/Card.astro';

const features = (await getCollection('features')).sort(
  (a, b) => a.data.order - b.data.order,
);
---
<Section id="features" class="bg-gray-50">
  <div class="mx-auto max-w-2xl text-center mb-16">
    <h2 class="text-3xl font-bold tracking-tight text-gray-900 sm:text-4xl">
      Built for teams that ship
    </h2>
    <p class="mt-4 text-lg text-gray-600">
      Everything you need, nothing you don't.
    </p>
  </div>

  <div class="grid gap-6 sm:grid-cols-2 lg:grid-cols-3">
    {features.map(({ data }) => (
      <Card>
        <div class="flex h-12 w-12 items-center justify-center rounded-lg bg-accent-100 text-accent-600 mb-4">
          {/* swap for a real icon system if user wants — see "Icons" below */}
          <span class="text-2xl" aria-hidden="true">★</span>
        </div>
        <h3 class="text-lg font-semibold text-gray-900">{data.title}</h3>
        <p class="mt-2 text-gray-600">{data.description}</p>
      </Card>
    ))}
  </div>
</Section>
```

## Islands (`src/components/islands/`)

### `MobileMenu.tsx` — when you actually need React

```tsx
import { useEffect, useState } from 'react';

interface NavItem {
  label: string;
  href: string;
}

interface Props {
  items: NavItem[];
  ctaLabel: string;
  ctaHref: string;
}

export default function MobileMenu({ items, ctaLabel, ctaHref }: Props) {
  const [open, setOpen] = useState(false);

  useEffect(() => {
    if (!open) return;
    const onEsc = (e: KeyboardEvent) => e.key === 'Escape' && setOpen(false);
    document.addEventListener('keydown', onEsc);
    document.body.style.overflow = 'hidden';
    return () => {
      document.removeEventListener('keydown', onEsc);
      document.body.style.overflow = '';
    };
  }, [open]);

  return (
    <>
      <button
        type="button"
        onClick={() => setOpen(true)}
        aria-label="Open menu"
        aria-expanded={open}
        className="md:hidden inline-flex items-center justify-center p-2 rounded-md text-gray-700 hover:bg-gray-100"
      >
        <svg className="h-6 w-6" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
        </svg>
      </button>

      {open && (
        <div className="fixed inset-0 z-50 md:hidden" role="dialog" aria-modal="true">
          <div className="fixed inset-0 bg-black/40" onClick={() => setOpen(false)} />
          <div className="fixed inset-y-0 right-0 w-full max-w-xs bg-white p-6 shadow-xl">
            <div className="flex items-center justify-end">
              <button
                type="button"
                onClick={() => setOpen(false)}
                aria-label="Close menu"
                className="p-2 rounded-md text-gray-700 hover:bg-gray-100"
              >
                <svg className="h-6 w-6" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
            <nav className="mt-6 flex flex-col gap-1">
              {items.map((item) => (
                <a
                  key={item.href}
                  href={item.href}
                  onClick={() => setOpen(false)}
                  className="rounded-md px-3 py-2 text-base font-medium text-gray-900 hover:bg-gray-100"
                >
                  {item.label}
                </a>
              ))}
              <a
                href={ctaHref}
                className="mt-4 rounded-lg bg-accent-500 px-4 py-2 text-center font-medium text-white hover:bg-accent-600"
              >
                {ctaLabel}
              </a>
            </nav>
          </div>
        </div>
      )}
    </>
  );
}
```

Used in the header like this:

```astro
---
// src/components/sections/Header.astro
import { getEntry } from 'astro:content';
import MobileMenu from '../islands/MobileMenu.tsx';
import Container from '../ui/Container.astro';
import Button from '../ui/Button.astro';

const settings = await getEntry('site', 'settings');
if (!settings) throw new Error('Site settings missing');
const { name, nav, cta } = settings.data;
---
<header class="sticky top-0 z-40 bg-white/80 backdrop-blur border-b border-gray-200">
  <Container as="nav" class="flex h-16 items-center justify-between">
    <a href="/" class="text-lg font-semibold">{name}</a>

    <div class="hidden md:flex items-center gap-8">
      {nav.map((item) => (
        <a href={item.href} class="text-sm font-medium text-gray-700 hover:text-gray-900">
          {item.label}
        </a>
      ))}
      <Button variant="primary" size="sm" href={cta.href}>{cta.label}</Button>
    </div>

    <MobileMenu client:idle items={nav} ctaLabel={cta.label} ctaHref={cta.href} />
  </Container>
</header>
```

`client:idle` is right here — the menu only matters once the page is stable, and on desktop it's hidden by CSS anyway.

### Theme toggle (when dark mode is wanted)

```tsx
// src/components/islands/ThemeToggle.tsx
import { useEffect, useState } from 'react';

export default function ThemeToggle() {
  const [theme, setTheme] = useState<'light' | 'dark'>('light');

  useEffect(() => {
    setTheme(document.documentElement.classList.contains('dark') ? 'dark' : 'light');
  }, []);

  const toggle = () => {
    const next = theme === 'dark' ? 'light' : 'dark';
    document.documentElement.classList.toggle('dark', next === 'dark');
    localStorage.setItem('theme', next);
    setTheme(next);
  };

  return (
    <button
      type="button"
      onClick={toggle}
      aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}
      className="p-2 rounded-md text-gray-700 hover:bg-gray-100 dark:text-gray-200 dark:hover:bg-gray-800"
    >
      {theme === 'dark' ? '☀️' : '🌙'}
    </button>
  );
}
```

Hydrate with `client:load` (the user might click immediately) or `client:idle` (acceptable; one-frame flash possible).

The pre-paint script in `BaseLayout` (see `tailwind-setup.md`) handles the initial class before this component mounts, so there's no flash on load.

## Icons

Three reasonable paths:

1. **Inline SVG per use** — fine for 2–5 distinct icons. Just paste them.
2. **`astro-icon`** — community integration, supports Iconify, lazy by default. Senior-grade choice for any non-trivial set. Query MCP: `Astro:search_astro_docs` → `"astro-icon integration"` for current install steps.
3. **`lucide-react` inside React islands** — only for the islands themselves. Don't add React just to get icons.

For 100% static + many icons → `astro-icon`. For a handful → inline SVG.

## What this section doesn't cover

For these, query the MCP rather than improvising:

- View Transitions / `<ClientRouter />` for SPA-style nav
- Form handling that requires server (use a third-party form service or an API route under SSR)
- Astro Actions
- Cross-island state sharing
