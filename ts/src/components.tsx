/**
 * Shared Ink primitives: framed panels, key chips, labelled fields, empty
 * states and the popup frame with its shadow.
 *
 * Every screen composes these instead of restating border and colour choices,
 * so a focus ring or a chip looks the same in the resource library, the
 * workbench and every modal.
 */
import React, { type ReactNode } from 'react';
import { Box, Text } from 'ink';
import {
  ACCENT,
  BORDER,
  DANGER,
  FOCUS,
  MUTED,
  RAISED,
  SELECTED_BG,
  SHADOW,
  SUCCESS,
  TEXT,
  WARN,
  truncate,
  width,
} from './text.js';

export interface Rect {
  x: number;
  y: number;
  width: number;
  height: number;
}

/**
 * Rounded, dim-bordered panel shared by every framed region.
 *
 * Ink draws the frame itself; `title` is rendered as a first-row overlay by
 * {@link Panel} because Ink has no border-title primitive.
 */
export function Panel({
  title,
  subtitle,
  children,
  color = BORDER,
  background,
  width: columns,
  height,
  flexGrow,
  flexShrink,
  titleColor = TEXT,
  subtitleColor = MUTED,
}: {
  title?: string;
  subtitle?: string;
  children?: ReactNode;
  color?: string;
  background?: string;
  width?: number;
  height?: number;
  flexGrow?: number;
  flexShrink?: number;
  titleColor?: string;
  subtitleColor?: string;
}): React.ReactElement {
  return (
    <Box
      flexDirection="column"
      borderStyle="round"
      borderColor={color}
      backgroundColor={background}
      width={columns}
      height={height}
      flexGrow={flexGrow}
      flexShrink={flexShrink}
    >
      {title !== undefined || subtitle !== undefined ? (
        <Box
          position="absolute"
          top={-1}
          left={2}
          height={1}
          width={columns === undefined ? undefined : Math.max(columns - 4, 1)}
          overflow="hidden"
        >
          {title !== undefined ? (
            <Text color={titleColor} bold wrap="truncate">
              {title}
            </Text>
          ) : null}
        </Box>
      ) : null}
      {children}
      {subtitle !== undefined ? (
        <Box
          position="absolute"
          bottom={-1}
          left={2}
          height={1}
          width={columns === undefined ? undefined : Math.max(columns - 4, 1)}
          overflow="hidden"
        >
          <Text color={subtitleColor} wrap="truncate">
            {subtitle}
          </Text>
        </Box>
      ) : null}
    </Box>
  );
}

/** Border colour for a region: accent when focused, plain otherwise. */
export function focusColor(focused: boolean): string {
  return focused ? ACCENT : BORDER;
}

/** Muted label followed by a value, for key/value header lines. */
export function Field({
  label,
  value,
  color = TEXT,
  bold,
}: {
  label: string;
  value: string;
  color?: string;
  bold?: boolean;
}): React.ReactElement {
  return (
    <Text wrap="truncate">
      {label.length > 0 ? <Text color={MUTED}>{label}</Text> : null}
      <Text color={color} bold={bold}>
        {value}
      </Text>
    </Text>
  );
}

/** A `[label]` action chip; disabled chips stay visible but dim. */
export function Chip({
  label,
  active,
  disabled,
}: {
  label: string;
  active?: boolean;
  disabled?: boolean;
}): React.ReactElement {
  return (
    <Text
      color={disabled ? MUTED : active ? FOCUS : TEXT}
      backgroundColor={active ? SELECTED_BG : RAISED}
      bold={active}
    >
      {` ${label} `}
    </Text>
  );
}

/**
 * Inline search field. It only occupies a row while editing or holding a query,
 * and its title names the keys that commit or revert the edit.
 */
export function SearchField({
  columns,
  value,
  editing,
  title,
}: {
  columns: number;
  value: string;
  editing: boolean;
  title: string;
}): React.ReactElement {
  return (
    <Box flexDirection="column" width={columns} height={3}>
      <Panel title={title} color={editing ? FOCUS : BORDER} width={columns} height={3}>
        <Box paddingX={1} height={1} width={columns - 2} overflow="hidden">
          <Text color={TEXT} wrap="truncate">
            {truncate(value, Math.max(columns - 4, 1))}
          </Text>
        </Box>
      </Panel>
      {editing && columns >= 30 ? (
        <Box position="absolute" top={1} left={Math.max(columns - 16, 0)} width={14} height={1}>
          <Text color={FOCUS}>[确认]</Text>
          <Text color={ACCENT}> [撤销]</Text>
        </Box>
      ) : null}
    </Box>
  );
}

/** Highlighted row marker used by every list. */
export const HIGHLIGHT = '› ';

/** Marker + colour for an asset row's usage state. */
export function assetMarker(active: boolean, matched: boolean): { marker: string; color: string } {
  if (active) {
    return { marker: '●已选用', color: SUCCESS };
  }
  if (matched) {
    return { marker: '✓匹配', color: ACCENT };
  }
  return { marker: ' ', color: MUTED };
}

/** Preparation state badge: label plus colour. */
export function preparationBadge(preparation: string): { label: string; color: string } {
  switch (preparation) {
    case 'chooseImage':
      return { label: '待选镜像', color: MUTED };
    case 'matching':
      return { label: '匹配中', color: ACCENT };
    case 'chooseSystem':
      return { label: '待选系统', color: WARN };
    case 'missingSymbols':
      return { label: '缺少符号', color: WARN };
    case 'chooseSymbols':
      return { label: '待选符号', color: WARN };
    case 'ready':
      return { label: '已就绪', color: SUCCESS };
    default:
      return { label: '已取消', color: DANGER };
  }
}

/**
 * Keep empty states within the pane, including very small terminals. The
 * heading survives first; guidance appears only when there is room for it.
 */
export function Empty({
  width: columns,
  height,
  title,
  hint,
}: {
  width: number;
  height: number;
  title: string;
  hint: string;
}): React.ReactElement | null {
  if (columns <= 0 || height <= 0) {
    return null;
  }
  const lines = height >= 3 ? 2 : 1;
  return (
    <Box
      position="absolute"
      top={Math.max(Math.floor((height - lines) / 2), 0)}
      left={0}
      width={columns}
      height={lines}
      flexDirection="column"
      alignItems="center"
    >
      <Text color={TEXT} bold wrap="truncate">
        {truncate(title, columns)}
      </Text>
      {lines > 1 ? (
        <Text color={MUTED} wrap="truncate">
          {truncate(hint, columns)}
        </Text>
      ) : null}
    </Box>
  );
}

/**
 * One-cell shadow along the popup's right and bottom edges, so modals read
 * above the content behind them.
 *
 * Rendered before the popup itself; it cannot draw outside the screen.
 */
export function Shadow({
  rect,
  columns,
  rows,
}: {
  rect: Rect;
  columns: number;
  rows: number;
}): React.ReactElement | null {
  const right = rect.x + rect.width;
  const bottom = rect.y + rect.height;
  if (right >= columns && bottom >= rows) {
    return null;
  }
  return (
    <>
      {right < columns ? (
        <Box
          position="absolute"
          top={rect.y + 1}
          left={right}
          width={1}
          height={Math.min(rect.height, rows - rect.y - 1)}
          backgroundColor={SHADOW}
        />
      ) : null}
      {bottom < rows ? (
        <Box
          position="absolute"
          top={bottom}
          left={rect.x + 1}
          width={Math.min(rect.width + 1, columns - rect.x - 1)}
          height={1}
          backgroundColor={SHADOW}
        />
      ) : null}
    </>
  );
}

/** Lay out `label: value` pairs across `columns`, dropping whole trailing pairs. */
export interface FitField {
  label: string;
  value: string;
  color?: string;
}

/**
 * Two rules, because the fields are not equally important:
 *
 * - A long *value* is shortened to leave room for the fields after it. A
 *   truncated path still identifies the image; a missing kernel does not.
 * - A field that cannot be shortened usefully is dropped whole, so the row never
 *   ends in a fragment like `M 匹…`.
 */
export function fitFields(fields: FitField[], columns: number): FitField[] {
  const total = fields
    .map((field, index) => (index > 0 ? 3 : 0) + width(field.label) + width(field.value))
    .reduce((a, b) => a + b, 0);
  const shorten = total > columns;
  const out: FitField[] = [];
  let used = 0;
  for (let index = 0; index < fields.length; index += 1) {
    const field = fields[index] as FitField;
    const gap = index > 0 ? 3 : 0;
    const labelWidth = width(field.label);
    const valueWidth = width(field.value);
    const remaining = columns - (used + gap + labelWidth);
    if (remaining <= 0) {
      break;
    }
    if (valueWidth <= remaining) {
      used += gap + labelWidth + valueWidth;
      out.push(field);
      continue;
    }
    const rest = fields
      .slice(index + 1)
      .map((entry) => 3 + width(entry.label) + width(entry.value))
      .reduce((a, b) => a + b, 0);
    const budget = shorten && rest > 0 && remaining > rest + 8 ? remaining - rest : remaining;
    if (budget < 8) {
      break;
    }
    out.push({ ...field, value: truncate(field.value, budget) });
    break;
  }
  return out;
}

/** Render fitted fields with dim separators between them. */
export function FitLine({
  fields,
  columns,
}: {
  fields: FitField[];
  columns: number;
}): React.ReactElement {
  const fitted = fitFields(fields, columns);
  return (
    <Box height={1} overflow="hidden">
      {fitted.map((field, index) => (
        <React.Fragment key={`${field.label}-${index}`}>
          {index > 0 ? <Text color={BORDER}> · </Text> : null}
          <Field label={field.label} value={field.value} color={field.color ?? TEXT} />
        </React.Fragment>
      ))}
    </Box>
  );
}

/** Status colour for a message: error text, running text, or ordinary text. */
export function statusColor(running: boolean, isError: boolean): string {
  return isError ? DANGER : running ? ACCENT : TEXT;
}
