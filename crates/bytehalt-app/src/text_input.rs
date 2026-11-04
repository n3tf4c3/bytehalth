#![allow(dead_code)] // módulo copiado do NetLane; nem todas as funções são usadas aqui.
//! Campo de texto de uma linha (renomear abas e grupos, filtrar temas, formulários).
//! No modo mascarado (senhas, códigos), mostra só pontos e não copia para a área
//! de transferência.
//!
//! Adaptado do exemplo `crates/gpui/examples/input.rs` do Zed (Apache-2.0), que
//! integra o campo ao IME do sistema por `EntityInputHandler`.

use std::ops::Range;

use gpui::{
    App, Bounds, ClipboardItem, Context, CursorStyle, ElementInputHandler, Entity, EntityInputHandler, EventEmitter, FocusHandle, Focusable, KeyBinding,
    MouseButton, MouseDownEvent, MouseMoveEvent, MouseUpEvent, Pixels, Point, ShapedLine, SharedString, TextRun, UTF16Selection, UnderlineStyle, Window,
    actions, canvas, div, fill, point, prelude::*, px, size,
};

use crate::theme::ActiveTheme;

actions!(text_input, [Backspace, Delete, Left, Right, SelectLeft, SelectRight, SelectAll, Home, End, SelectHome, SelectEnd, Paste, Cut, Copy, Confirm, Cancel]);

pub fn bind_keys(cx: &mut App) {
    let ctx = Some("TextInput");
    cx.bind_keys([
        KeyBinding::new("backspace", Backspace, ctx),
        KeyBinding::new("delete", Delete, ctx),
        KeyBinding::new("left", Left, ctx),
        KeyBinding::new("right", Right, ctx),
        KeyBinding::new("shift-left", SelectLeft, ctx),
        KeyBinding::new("shift-right", SelectRight, ctx),
        KeyBinding::new("ctrl-a", SelectAll, ctx),
        KeyBinding::new("home", Home, ctx),
        KeyBinding::new("end", End, ctx),
        KeyBinding::new("shift-home", SelectHome, ctx),
        KeyBinding::new("shift-end", SelectEnd, ctx),
        KeyBinding::new("ctrl-v", Paste, ctx),
        KeyBinding::new("ctrl-x", Cut, ctx),
        KeyBinding::new("ctrl-c", Copy, ctx),
        KeyBinding::new("enter", Confirm, ctx),
        KeyBinding::new("escape", Cancel, ctx),
    ]);
}

pub enum TextInputEvent {
    Changed,
    Confirmed,
    Cancelled,
}

pub struct TextInput {
    focus: FocusHandle,
    content: String,
    placeholder: SharedString,
    selected: Range<usize>,
    reversed: bool,
    marked: Option<Range<usize>>,
    last_line: Option<ShapedLine>,
    last_bounds: Option<Bounds<Pixels>>,
    scroll_x: Pixels,
    #[cfg(all(test, feature = "gui-test"))]
    last_content_mask: Option<Bounds<Pixels>>,
    #[cfg(all(test, feature = "gui-test"))]
    last_cursor_bounds: Option<Bounds<Pixels>>,
    selecting: bool,
    masked: bool,
}

impl Drop for TextInput {
    fn drop(&mut self) {
        if self.masked {
            zeroize::Zeroize::zeroize(&mut self.content);
        }
    }
}

/// Caractere mostrado no lugar de cada caractere de um campo mascarado.
const MASK: char = '•';

impl EventEmitter<TextInputEvent> for TextInput {}

impl TextInput {
    pub fn new(content: impl Into<String>, placeholder: impl Into<SharedString>, cx: &mut Context<Self>) -> Self {
        let content = content.into();
        let len = content.len();
        Self {
            focus: cx.focus_handle(),
            content,
            placeholder: placeholder.into(),
            selected: 0..len,
            reversed: false,
            marked: None,
            last_line: None,
            last_bounds: None,
            scroll_x: px(0.),
            #[cfg(all(test, feature = "gui-test"))]
            last_content_mask: None,
            #[cfg(all(test, feature = "gui-test"))]
            last_cursor_bounds: None,
            selecting: false,
            masked: false,
        }
    }

    /// Inclui o campo na navegação por Tab, na ordem de `index`.
    /// Campo de senha/código: mostra pontos, não copia e zera o conteúdo ao descartar.
    pub fn masked(mut self) -> Self {
        self.masked = true;
        self
    }

    pub fn tab_stop(mut self, index: isize) -> Self {
        self.focus = self.focus.clone().tab_index(index).tab_stop(true);
        self
    }

    pub fn text(&self) -> &str {
        &self.content
    }

    pub fn set_text(&mut self, text: impl Into<String>, cx: &mut Context<Self>) {
        if self.masked {
            zeroize::Zeroize::zeroize(&mut self.content);
        }
        self.content = text.into();
        self.selected = self.content.len()..self.content.len();
        self.marked = None;
        self.scroll_x = px(0.);
        cx.emit(TextInputEvent::Changed);
        cx.notify();
    }

    /// Posição na linha desenhada, que no modo mascarado tem só pontos.
    fn display_offset(&self, offset: usize) -> usize {
        if self.masked { self.content[..offset].chars().count() * MASK.len_utf8() } else { offset }
    }

    fn content_offset(&self, offset: usize) -> usize {
        if self.masked { self.content.char_indices().nth(offset / MASK.len_utf8()).map_or(self.content.len(), |(i, _)| i) } else { offset }
    }

    fn cursor(&self) -> usize {
        if self.reversed { self.selected.start } else { self.selected.end }
    }

    fn prev(&self, offset: usize) -> usize {
        self.content[..offset].char_indices().next_back().map_or(0, |(i, _)| i)
    }

    fn next(&self, offset: usize) -> usize {
        self.content[offset..].chars().next().map_or(offset, |c| offset + c.len_utf8())
    }

    fn move_to(&mut self, offset: usize, cx: &mut Context<Self>) {
        self.selected = offset..offset;
        cx.notify();
    }

    fn select_to(&mut self, offset: usize, cx: &mut Context<Self>) {
        if self.reversed {
            self.selected.start = offset;
        } else {
            self.selected.end = offset;
        }
        if self.selected.end < self.selected.start {
            self.reversed = !self.reversed;
            self.selected = self.selected.end..self.selected.start;
        }
        cx.notify();
    }

    fn left(&mut self, _: &Left, _: &mut Window, cx: &mut Context<Self>) {
        let to = if self.selected.is_empty() { self.prev(self.cursor()) } else { self.selected.start };
        self.move_to(to, cx);
    }

    fn right(&mut self, _: &Right, _: &mut Window, cx: &mut Context<Self>) {
        let to = if self.selected.is_empty() { self.next(self.cursor()) } else { self.selected.end };
        self.move_to(to, cx);
    }

    fn select_left(&mut self, _: &SelectLeft, _: &mut Window, cx: &mut Context<Self>) {
        self.select_to(self.prev(self.cursor()), cx);
    }

    fn select_right(&mut self, _: &SelectRight, _: &mut Window, cx: &mut Context<Self>) {
        self.select_to(self.next(self.cursor()), cx);
    }

    fn select_all(&mut self, _: &SelectAll, _: &mut Window, cx: &mut Context<Self>) {
        self.selected = 0..self.content.len();
        self.reversed = false;
        cx.notify();
    }

    fn home(&mut self, _: &Home, _: &mut Window, cx: &mut Context<Self>) {
        self.move_to(0, cx);
    }

    fn end(&mut self, _: &End, _: &mut Window, cx: &mut Context<Self>) {
        self.move_to(self.content.len(), cx);
    }

    fn select_home(&mut self, _: &SelectHome, _: &mut Window, cx: &mut Context<Self>) {
        self.select_to(0, cx);
    }

    fn select_end(&mut self, _: &SelectEnd, _: &mut Window, cx: &mut Context<Self>) {
        self.select_to(self.content.len(), cx);
    }

    fn backspace(&mut self, _: &Backspace, window: &mut Window, cx: &mut Context<Self>) {
        if self.selected.is_empty() {
            self.select_to(self.prev(self.cursor()), cx);
        }
        self.replace_text_in_range(None, "", window, cx);
    }

    fn delete(&mut self, _: &Delete, window: &mut Window, cx: &mut Context<Self>) {
        if self.selected.is_empty() {
            self.select_to(self.next(self.cursor()), cx);
        }
        self.replace_text_in_range(None, "", window, cx);
    }

    fn paste(&mut self, _: &Paste, window: &mut Window, cx: &mut Context<Self>) {
        if let Some(text) = cx.read_from_clipboard().and_then(|item| item.text()) {
            self.replace_text_in_range(None, &text.replace(['\r', '\n'], " "), window, cx);
        }
    }

    fn copy(&mut self, _: &Copy, _: &mut Window, cx: &mut Context<Self>) {
        if !self.selected.is_empty() && !self.masked {
            cx.write_to_clipboard(ClipboardItem::new_string(self.content[self.selected.clone()].to_string()));
        }
    }

    fn cut(&mut self, _: &Cut, window: &mut Window, cx: &mut Context<Self>) {
        if !self.selected.is_empty() && !self.masked {
            cx.write_to_clipboard(ClipboardItem::new_string(self.content[self.selected.clone()].to_string()));
            self.replace_text_in_range(None, "", window, cx);
        }
    }

    fn confirm(&mut self, _: &Confirm, _: &mut Window, cx: &mut Context<Self>) {
        cx.emit(TextInputEvent::Confirmed);
    }

    fn cancel(&mut self, _: &Cancel, _: &mut Window, cx: &mut Context<Self>) {
        cx.emit(TextInputEvent::Cancelled);
    }

    fn index_at(&self, position: Point<Pixels>) -> usize {
        match (&self.last_bounds, &self.last_line) {
            (Some(bounds), Some(line)) if !self.content.is_empty() => self.content_offset(line.closest_index_for_x(position.x - bounds.left() + self.scroll_x)),
            _ => 0,
        }
    }

    fn mouse_down(&mut self, e: &MouseDownEvent, window: &mut Window, cx: &mut Context<Self>) {
        window.focus(&self.focus, cx);
        self.selecting = true;
        let i = self.index_at(e.position);
        if e.modifiers.shift { self.select_to(i, cx) } else { self.move_to(i, cx) }
    }

    fn mouse_move(&mut self, e: &MouseMoveEvent, _: &mut Window, cx: &mut Context<Self>) {
        if self.selecting {
            self.select_to(self.index_at(e.position), cx);
        }
    }

    fn mouse_up(&mut self, _: &MouseUpEvent, _: &mut Window, _: &mut Context<Self>) {
        self.selecting = false;
    }

    fn offset_to_utf16(&self, offset: usize) -> usize {
        self.content[..offset.min(self.content.len())].encode_utf16().count()
    }

    fn offset_from_utf16(&self, offset: usize) -> usize {
        let mut units = 0;
        for (i, ch) in self.content.char_indices() {
            if units >= offset {
                return i;
            }
            units += ch.len_utf16();
        }
        self.content.len()
    }

    fn range_to_utf16(&self, r: &Range<usize>) -> Range<usize> {
        self.offset_to_utf16(r.start)..self.offset_to_utf16(r.end)
    }

    fn range_from_utf16(&self, r: &Range<usize>) -> Range<usize> {
        self.offset_from_utf16(r.start)..self.offset_from_utf16(r.end)
    }
}

impl Focusable for TextInput {
    fn focus_handle(&self, _: &App) -> FocusHandle {
        self.focus.clone()
    }
}

impl EntityInputHandler for TextInput {
    fn text_for_range(&mut self, range: Range<usize>, actual: &mut Option<Range<usize>>, _: &mut Window, _: &mut Context<Self>) -> Option<String> {
        let range = self.range_from_utf16(&range);
        actual.replace(self.range_to_utf16(&range));
        Some(self.content[range].to_string())
    }

    fn selected_text_range(&mut self, _: bool, _: &mut Window, _: &mut Context<Self>) -> Option<UTF16Selection> {
        Some(UTF16Selection { range: self.range_to_utf16(&self.selected), reversed: self.reversed })
    }

    fn marked_text_range(&self, _: &mut Window, _: &mut Context<Self>) -> Option<Range<usize>> {
        self.marked.as_ref().map(|r| self.range_to_utf16(r))
    }

    fn unmark_text(&mut self, _: &mut Window, _: &mut Context<Self>) {
        self.marked = None;
    }

    fn replace_text_in_range(&mut self, range: Option<Range<usize>>, text: &str, _: &mut Window, cx: &mut Context<Self>) {
        let range = range.map(|r| self.range_from_utf16(&r)).or(self.marked.clone()).unwrap_or(self.selected.clone());
        self.content.replace_range(range.clone(), text);
        let end = range.start + text.len();
        self.selected = end..end;
        self.marked = None;
        cx.emit(TextInputEvent::Changed);
        cx.notify();
    }

    fn replace_and_mark_text_in_range(
        &mut self,
        range: Option<Range<usize>>,
        text: &str,
        new_selected: Option<Range<usize>>,
        _: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let range = range.map(|r| self.range_from_utf16(&r)).or(self.marked.clone()).unwrap_or(self.selected.clone());
        self.content.replace_range(range.clone(), text);
        self.marked = (!text.is_empty()).then(|| range.start..range.start + text.len());
        self.selected = new_selected.map(|r| self.range_from_utf16(&r)).map(|r| r.start + range.start..r.end + range.start).unwrap_or_else(|| {
            let end = range.start + text.len();
            end..end
        });
        cx.notify();
    }

    fn bounds_for_range(&mut self, range: Range<usize>, bounds: Bounds<Pixels>, _: &mut Window, _: &mut Context<Self>) -> Option<Bounds<Pixels>> {
        let line = self.last_line.as_ref()?;
        let range = self.range_from_utf16(&range);
        let x = |offset| (line.x_for_index(self.display_offset(offset)) - self.scroll_x).clamp(px(0.), bounds.size.width);
        Some(Bounds::from_corners(point(bounds.left() + x(range.start), bounds.top()), point(bounds.left() + x(range.end), bounds.bottom())))
    }

    fn character_index_for_point(&mut self, p: Point<Pixels>, _: &mut Window, _: &mut Context<Self>) -> Option<usize> {
        let bounds = self.last_bounds?;
        let line = self.last_line.as_ref()?;
        let local = bounds.localize(&p)?;
        Some(self.offset_to_utf16(self.content_offset(line.closest_index_for_x(local.x + self.scroll_x))))
    }
}

impl Render for TextInput {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let entity = cx.entity();
        let line_height = window.line_height();
        div()
            .key_context("TextInput")
            .track_focus(&self.focus)
            .cursor(CursorStyle::IBeam)
            .w_full()
            .min_w_0()
            .overflow_hidden()
            .on_action(cx.listener(Self::backspace))
            .on_action(cx.listener(Self::delete))
            .on_action(cx.listener(Self::left))
            .on_action(cx.listener(Self::right))
            .on_action(cx.listener(Self::select_left))
            .on_action(cx.listener(Self::select_right))
            .on_action(cx.listener(Self::select_all))
            .on_action(cx.listener(Self::home))
            .on_action(cx.listener(Self::end))
            .on_action(cx.listener(Self::select_home))
            .on_action(cx.listener(Self::select_end))
            .on_action(cx.listener(Self::paste))
            .on_action(cx.listener(Self::cut))
            .on_action(cx.listener(Self::copy))
            .on_action(cx.listener(Self::confirm))
            .on_action(cx.listener(Self::cancel))
            .on_mouse_down(MouseButton::Left, cx.listener(Self::mouse_down))
            .on_mouse_move(cx.listener(Self::mouse_move))
            .on_mouse_up(MouseButton::Left, cx.listener(Self::mouse_up))
            .child(canvas(|_, _, _| {}, move |bounds, _, window, cx| paint(&entity, bounds, window, cx)).w_full().h(line_height))
    }
}

fn paint(entity: &Entity<TextInput>, bounds: Bounds<Pixels>, window: &mut Window, cx: &mut App) {
    #[cfg(all(test, feature = "gui-test"))]
    let content_mask = window.content_mask().bounds;
    let t = cx.theme().clone();
    let input = entity.read(cx);
    let focus = input.focus.clone();
    let style = window.text_style();
    let (text, color): (SharedString, _) = if input.content.is_empty() {
        (input.placeholder.clone(), t.text_faint)
    } else if input.masked {
        (MASK.to_string().repeat(input.content.chars().count()).into(), t.text)
    } else {
        (input.content.clone().into(), t.text)
    };
    let base = TextRun { len: text.len(), font: style.font(), color, background_color: None, underline: None, strikethrough: None };
    let marked = input.marked.as_ref().map(|m| input.display_offset(m.start)..input.display_offset(m.end));
    let runs = match &marked {
        Some(m) if !input.content.is_empty() => [
            TextRun { len: m.start, ..base.clone() },
            TextRun { len: m.end - m.start, underline: Some(UnderlineStyle { color: Some(color), thickness: px(1.), wavy: false }), ..base.clone() },
            TextRun { len: text.len() - m.end, ..base },
        ]
        .into_iter()
        .filter(|r| r.len > 0)
        .collect(),
        _ => vec![base],
    };
    let selected = input.display_offset(input.selected.start)..input.display_offset(input.selected.end);
    let cursor = input.display_offset(input.cursor());
    let empty = input.content.is_empty();
    let focused = focus.is_focused(window);
    let previous_scroll = input.scroll_x;

    window.handle_input(&focus, ElementInputHandler::new(bounds, entity.clone()), cx);
    let font_size = style.font_size.to_pixels(window.rem_size());
    let line = window.text_system().shape_line(text, font_size, &runs, None);
    let height = bounds.size.height;
    let caret_width = px(1.5);
    let viewport_width = (bounds.size.width - caret_width).max(px(0.));
    let cursor_x = if empty { px(0.) } else { line.x_for_index(cursor) };
    // Mantém a linha inteira; só desloca a pintura para revelar o cursor.
    // Ao apagar ou ampliar o campo, limita o deslocamento ao conteúdo restante.
    let scroll_x = if empty {
        px(0.)
    } else {
        let max_scroll = (line.width - viewport_width).max(px(0.));
        let scroll = previous_scroll.clamp(px(0.), max_scroll);
        if focused { scroll.max(cursor_x - viewport_width).min(cursor_x).max(px(0.)) } else { scroll }
    };
    let origin = point(bounds.left() - scroll_x, bounds.top());
    if focused && !selected.is_empty() && !empty {
        let x0 = line.x_for_index(selected.start);
        let x1 = line.x_for_index(selected.end);
        window.paint_quad(fill(Bounds::new(point(origin.x + x0, bounds.top()), size(x1 - x0, height)), t.selection));
    }
    let _ = line.paint(origin, window.line_height(), gpui::TextAlign::Left, None, window, cx);
    let caret = (focused && selected.is_empty()).then(|| Bounds::new(point(origin.x + cursor_x, bounds.top()), size(caret_width, height)));
    if let Some(caret) = caret {
        window.paint_quad(fill(caret, t.accent));
    }
    entity.update(cx, |input, _| {
        input.last_line = Some(line);
        input.last_bounds = Some(bounds);
        input.scroll_x = scroll_x;
        #[cfg(all(test, feature = "gui-test"))]
        {
            input.last_content_mask = Some(content_mask);
            input.last_cursor_bounds = caret;
        }
    });
}
