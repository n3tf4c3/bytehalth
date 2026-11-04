#![allow(dead_code)] // módulo copiado do NetLane.
//! A visible scroll position indicator for GPUI divs, without changing their layout.
use crate::theme::ActiveTheme;
use gpui::{
    App, Bounds, Div, Element, ElementId, GlobalElementId, Hsla, InspectorElementId, IntoElement, LayoutId, Pixels, ScrollHandle, Stateful, Window, fill,
    point, prelude::*, px, size,
};

pub trait ScrollbarExt {
    fn with_scrollbar(self, cx: &App) -> Scrollbar;
    fn with_scrollbar_for(self, handle: &ScrollHandle, cx: &App) -> Scrollbar;
}

impl ScrollbarExt for Stateful<Div> {
    fn with_scrollbar(self, cx: &App) -> Scrollbar {
        Scrollbar { inner: Some(self), handle: ScrollHandle::new(), persistent_handle: false, color: cx.theme().text_muted }
    }

    fn with_scrollbar_for(self, handle: &ScrollHandle, cx: &App) -> Scrollbar {
        Scrollbar { handle: handle.clone(), persistent_handle: true, ..self.with_scrollbar(cx) }
    }
}

pub struct Scrollbar {
    inner: Option<Stateful<Div>>,
    handle: ScrollHandle,
    persistent_handle: bool,
    color: Hsla,
}

impl IntoElement for Scrollbar {
    type Element = Self;

    fn into_element(self) -> Self {
        self
    }
}

impl Element for Scrollbar {
    type RequestLayoutState = <Stateful<Div> as Element>::RequestLayoutState;
    type PrepaintState = <Stateful<Div> as Element>::PrepaintState;

    fn id(&self) -> Option<ElementId> {
        self.inner.as_ref().unwrap().id()
    }

    fn source_location(&self) -> Option<&'static std::panic::Location<'static>> {
        self.inner.as_ref().unwrap().source_location()
    }

    fn request_layout(
        &mut self,
        id: Option<&GlobalElementId>,
        inspector_id: Option<&InspectorElementId>,
        window: &mut Window,
        cx: &mut App,
    ) -> (LayoutId, Self::RequestLayoutState) {
        if !self.persistent_handle {
            // Keep the offset across renders, keyed by the original div's ID.
            self.handle = window.with_element_state(id.expect("scrollbar requires an ID"), |old, _| {
                let handle: ScrollHandle = old.unwrap_or_default();
                (handle.clone(), handle)
            });
        }
        self.inner = Some(self.inner.take().unwrap().track_scroll(&self.handle));
        self.inner.as_mut().unwrap().request_layout(id, inspector_id, window, cx)
    }

    fn prepaint(
        &mut self,
        id: Option<&GlobalElementId>,
        inspector_id: Option<&InspectorElementId>,
        bounds: Bounds<Pixels>,
        layout: &mut Self::RequestLayoutState,
        window: &mut Window,
        cx: &mut App,
    ) -> Self::PrepaintState {
        self.inner.as_mut().unwrap().prepaint(id, inspector_id, bounds, layout, window, cx)
    }

    fn paint(
        &mut self,
        id: Option<&GlobalElementId>,
        inspector_id: Option<&InspectorElementId>,
        bounds: Bounds<Pixels>,
        layout: &mut Self::RequestLayoutState,
        prepaint: &mut Self::PrepaintState,
        window: &mut Window,
        cx: &mut App,
    ) {
        self.inner.as_mut().unwrap().paint(id, inspector_id, bounds, layout, prepaint, window, cx);
        let max = self.handle.max_offset().y;
        let viewport = bounds.size.height;
        if max <= px(0.) || viewport <= px(8.) {
            return;
        }
        let track = viewport - px(8.);
        let thumb = (track * (viewport / (viewport + max))).max(px(24.)).min(track);
        let progress = (-self.handle.offset().y / max).clamp(0., 1.);
        let thumb_bounds = Bounds::new(point(bounds.right() - px(7.), bounds.top() + px(4.) + (track - thumb) * progress), size(px(4.), thumb));
        // Paint after the content so the indicator stays at the viewport edge.
        // No hitbox: wheel input still reaches the original scrollable div.
        window.paint_quad(fill(thumb_bounds, self.color).corner_radii(px(2.)));
    }
}
