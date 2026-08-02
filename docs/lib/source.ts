import { docs } from "@/.source/server"
import { loader } from "@hanzo/docs/core/source"

export const source = loader({
  baseUrl: "/docs",
  source: docs.toSource(),
})
