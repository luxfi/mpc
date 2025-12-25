import { docs } from "@/.source"
import { loader } from "@hanzo/ui"

let _source: ReturnType<typeof loader> | null = null

export function getSource() {
  if (!_source) {
    _source = loader({
      baseUrl: "/docs",
      source: docs.toFumadocsSource(),
    })
  }
  return _source
}

export const source = getSource()
