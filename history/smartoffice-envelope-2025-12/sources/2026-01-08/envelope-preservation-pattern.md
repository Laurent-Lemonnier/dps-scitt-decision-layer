# Envelope Preservation Pattern — Smart Office

## Problem Statement

When a workflow passes through an **LLM node** (e.g., OpenAI, Anthropic), the LLM does NOT preserve the input envelope. The LLM node only outputs the generated content (text, JSON, etc.), losing all context from the original envelope including:

- `payload.context`
- `payload.memory`
- `payload.registry`
- `agent` metadata
- `execution` state
- All other envelope fields

This creates a critical problem: **how do we preserve the envelope while still using LLM capabilities?**

## Solution: Dual-Path Merge Pattern

The solution implemented in the Agent workflow uses a **dual-path merge pattern**:

```
                    ┌─────────────┐
                    │ Plan Prompt │
                    └──────┬──────┘
                           │
                    ┌──────┴──────┐
                    │             │
            Path 1: LLM      Path 2: Preserve
                    │             │
          ┌─────────▼──────┐  ┌──▼──────────┐
          │  Plan LLM      │  │ Keep        │
          │  (OpenAI)      │  │ Envelope    │
          └─────────┬──────┘  └──┬──────────┘
                    │             │
                    └──────┬──────┘
                           │
                    ┌──────▼──────────┐
                    │ Merge Plan +    │
                    │ Envelope        │
                    └──────┬──────────┘
                           │
                    ┌──────▼──────────┐
                    │ Plan Compile    │
                    │ (Extract & Merge)│
                    └─────────────────┘
```

### Step-by-Step Flow

1. **Plan Prompt** (Code Node)
   - Prepares LLM messages in `state.llm.messages`
   - Outputs the same envelope on TWO paths

2. **Path 1: LLM Processing**
   - `Plan LLM (OpenAI)` receives the envelope
   - Uses `state.llm.messages` to call the LLM
   - Outputs ONLY the LLM response (envelope is lost)

3. **Path 2: Envelope Preservation**
   - `Keep Envelope` receives the envelope
   - Removes `llm.messages` (not needed for preservation)
   - Passes through the preserved envelope

4. **Merge Node**
   - n8n Merge node (type: `mergeByPosition`)
   - Input 0: LLM output (only contains generated content)
   - Input 1: Preserved envelope (full state)
   - Configuration: `preferInput2` (prefer the envelope)
   - Result: Merged object with both LLM output fields AND envelope fields

5. **Plan Compile** (Code Node)
   - Receives merged data
   - Extracts LLM output from various possible fields (`output`, `data`, `response`, `text`)
   - Parses and validates the steps array
   - **Injects** the parsed steps into `merged.plan.steps`
   - Returns the complete envelope with LLM-generated plan

## Implementation Details

### Keep Envelope Node

```javascript
// This branch preserves the envelope while the LLM processes the request
// The envelope will be merged with LLM output in the next node
// This is critical because LLM nodes do NOT preserve the envelope
const state = items[0].json;

// Remove llm.messages to avoid passing them in the preserved envelope
// (they're only needed for the LLM call, not for preservation)
if (state.llm && state.llm.messages) {
  const preserved = { ...state };
  delete preserved.llm;
  return [{ json: preserved }];
}

return items;
```

### Plan Compile Node (Intelligent Merge)

```javascript
// Merge node provides merged data where:
// - LLM output is in the first item's json (from input 0)
// - Preserved envelope is overlaid (from input 1, preferInput2)
// We need to extract LLM output and inject it into the envelope

const merged = items[0].json;

// The LLM output can be in different fields depending on n8n version
let llmOutput = merged.output || merged.data || merged.response || merged.text || {};

// Handle both direct step array and wrapped response
let steps = null;
if (Array.isArray(llmOutput)) {
  steps = llmOutput;
} else if (llmOutput.steps && Array.isArray(llmOutput.steps)) {
  steps = llmOutput.steps;
} else if (typeof llmOutput === 'string') {
  // Try to parse if it's a JSON string
  try {
    const parsed = JSON.parse(llmOutput);
    steps = Array.isArray(parsed) ? parsed : (parsed.steps || null);
  } catch (e) {
    // Not JSON
    if (merged.llm && merged.llm.messages) {
      throw new Error("LLM output invalid: response not parseable as JSON");
    }
  }
}

if (!steps || !Array.isArray(steps)) {
  throw new Error("LLM output invalid: steps[] missing or not an array");
}

// Now inject the steps into the preserved envelope
merged.plan = merged.plan || {};
merged.plan.steps = steps.map(step => ({
  tool_ref: step.tool_ref || step.ref || step.tool,
  args: step.args || step.params || {},
  type: step.type || 'tool'
}));

merged.authorization = {
  mode: "human_required"
};

// Clean up temporary LLM fields
delete merged.llm;

return [{ json: merged }];
```

## Key Principles

1. **Never Trust LLM Nodes to Preserve State**
   - Always create a bypass path for the envelope
   - Use n8n Merge nodes to recombine

2. **Explicit Merge Logic**
   - Don't rely on automatic merging
   - Write explicit code to extract LLM output and inject into envelope

3. **Flexible Output Parsing**
   - LLM outputs vary by provider and version
   - Check multiple possible fields (`output`, `data`, `response`, `text`)
   - Handle both raw arrays and wrapped objects
   - Support JSON string responses

4. **Clean Up Temporary Fields**
   - Remove `llm` object after processing (not needed downstream)
   - Keep envelope clean for Executor

## Benefits

- ✅ **Complete envelope preservation** through LLM calls
- ✅ **No data loss** of context, memory, or metadata
- ✅ **Flexible** to different LLM providers and response formats
- ✅ **Explicit** merge logic (no hidden assumptions)
- ✅ **Aligned** with SmartOffice architecture principles

## When to Use This Pattern

Use the dual-path merge pattern whenever:

1. You need to call an LLM (or any external service that doesn't preserve envelope)
2. The downstream processing needs the full envelope context
3. The LLM output needs to be integrated into a specific envelope field

## Related Documentation

- [Agent Runtime](./agent-runtime.md) - Agent workflow architecture
- [ArchiPlan](./doc/.codex/ArchiPlan.md) - Overall architecture design
- [Executor Runtime](./executor-runtime.md) - Executor workflow architecture
