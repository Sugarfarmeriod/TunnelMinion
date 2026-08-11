import { useCallback, useEffect, useRef } from "react";
import type { KeyboardEvent as ReactKeyboardEvent, RefObject } from "react";

const FOCUSABLE_SELECTOR = [
  "a[href]",
  "area[href]",
  "button",
  "input:not([type='hidden'])",
  "select",
  "textarea",
  "iframe",
  "object",
  "embed",
  "[contenteditable='true']",
  "[tabindex]",
].join(", ");

function isInertOrHidden(element: HTMLElement): boolean {
  return (
    element.hasAttribute("hidden") ||
    element.getAttribute("aria-hidden") === "true" ||
    element.closest("[hidden], [inert]") !== null
  );
}

function isFocusableElement(element: HTMLElement): boolean {
  return (
    element.isConnected &&
    !isInertOrHidden(element) &&
    !element.matches(":disabled") &&
    element.getAttribute("aria-disabled") !== "true" &&
    (element.tabIndex >= 0 || element.matches("[contenteditable='true']"))
  );
}

function canRestoreFocus(element: HTMLElement | null): element is HTMLElement {
  return (
    element !== null &&
    element.isConnected &&
    element !== element.ownerDocument.body &&
    element !== element.ownerDocument.documentElement &&
    !isInertOrHidden(element) &&
    !element.matches(":disabled") &&
    element.getAttribute("aria-disabled") !== "true"
  );
}

function getFocusableElements(container: HTMLElement): HTMLElement[] {
  return Array.from(
    container.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR),
  ).filter(isFocusableElement);
}

export interface UseDialogFocusTrapOptions {
  initialFocusRef: RefObject<HTMLElement | null>;
  returnFocus?: readonly (HTMLElement | null)[];
  onEscape: () => void;
  escapeDisabled?: boolean;
}

export function useDialogFocusTrap<T extends HTMLElement>({
  initialFocusRef,
  returnFocus = [],
  onEscape,
  escapeDisabled = false,
}: UseDialogFocusTrapOptions): {
  dialogRef: RefObject<T | null>;
  handleKeyDown: (event: ReactKeyboardEvent<T>) => void;
} {
  const dialogRef = useRef<T | null>(null);
  const returnFocusRef = useRef<readonly (HTMLElement | null)[]>(returnFocus);
  returnFocusRef.current = returnFocus;

  const focusSafeTarget = useCallback(() => {
    const dialog = dialogRef.current;
    if (dialog === null) {
      return;
    }

    const initial = initialFocusRef.current;
    const controls = getFocusableElements(dialog);
    const target =
      initial !== null &&
      dialog.contains(initial) &&
      isFocusableElement(initial)
        ? initial
        : controls[0];
    if (target !== undefined) {
      target.focus();
      return;
    }
    if (canRestoreFocus(dialog)) {
      dialog.focus();
    }
  }, [initialFocusRef]);

  useEffect(() => {
    const dialog = dialogRef.current;
    if (dialog === null) {
      return;
    }
    if (dialog.getAttribute("tabindex") === null) {
      dialog.tabIndex = -1;
    }

    const document = dialog.ownerDocument;
    const handleFocusIn = (event: FocusEvent) => {
      const target = event.target;
      if (
        target instanceof Node &&
        dialog.contains(target) &&
        (target === dialog ||
          (target instanceof HTMLElement && isFocusableElement(target)))
      ) {
        return;
      }
      focusSafeTarget();
    };
    const preventOutsideInteraction = (event: Event) => {
      const target = event.target;
      if (target instanceof Node && dialog.contains(target)) {
        return;
      }
      event.preventDefault();
      event.stopPropagation();
      focusSafeTarget();
    };
    const interactionEvents = [
      "pointerdown",
      "mousedown",
      "touchstart",
      "click",
    ];

    document.addEventListener("focusin", handleFocusIn, true);
    for (const eventName of interactionEvents) {
      document.addEventListener(eventName, preventOutsideInteraction, true);
    }
    focusSafeTarget();

    return () => {
      document.removeEventListener("focusin", handleFocusIn, true);
      for (const eventName of interactionEvents) {
        document.removeEventListener(
          eventName,
          preventOutsideInteraction,
          true,
        );
      }
      const target = returnFocusRef.current.find(canRestoreFocus);
      target?.focus();
    };
  }, [focusSafeTarget]);

  useEffect(() => {
    const dialog = dialogRef.current;
    if (dialog === null) {
      return;
    }
    const active = dialog.ownerDocument.activeElement;
    if (
      active === dialog ||
      (active instanceof HTMLElement &&
        dialog.contains(active) &&
        isFocusableElement(active))
    ) {
      return;
    }
    focusSafeTarget();
  }, [escapeDisabled, focusSafeTarget]);

  const handleKeyDown = useCallback(
    (event: ReactKeyboardEvent<T>) => {
      if (event.key === "Escape") {
        if (!escapeDisabled) {
          event.preventDefault();
          onEscape();
        }
        return;
      }
      if (event.key !== "Tab") {
        return;
      }

      event.preventDefault();
      const dialog = dialogRef.current;
      if (dialog === null) {
        return;
      }
      const controls = getFocusableElements(dialog);
      if (controls.length === 0) {
        focusSafeTarget();
        return;
      }

      const active = dialog.ownerDocument.activeElement;
      const currentIndex =
        active instanceof HTMLElement ? controls.indexOf(active) : -1;
      const nextIndex = event.shiftKey
        ? currentIndex <= 0
          ? controls.length - 1
          : currentIndex - 1
        : currentIndex < 0 || currentIndex === controls.length - 1
          ? 0
          : currentIndex + 1;
      controls[nextIndex]?.focus();
      if (dialog.ownerDocument.activeElement !== controls[nextIndex]) {
        focusSafeTarget();
      }
    },
    [escapeDisabled, focusSafeTarget, onEscape],
  );

  return { dialogRef, handleKeyDown };
}
