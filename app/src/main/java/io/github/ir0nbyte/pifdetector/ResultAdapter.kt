package io.github.ir0nbyte.pifdetector

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ImageView
import android.widget.TextView
import androidx.core.content.ContextCompat
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView

class ResultAdapter : ListAdapter<DetectionResult, ResultAdapter.ViewHolder>(DIFF) {

    /*
     * Which rows are showing their evidence, keyed by flag. Position would
     * break the moment the list is resubmitted after a second run, and putting
     * it on the row itself would make DiffUtil treat an expand as a content
     * change and animate the whole row.
     */
    private val expanded = mutableSetOf<Int>()

    private fun toggle(flag: Int, position: Int) {
        if (!expanded.add(flag)) expanded.remove(flag)
        notifyItemChanged(position)
    }
    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_detection_result, parent, false)
        return ViewHolder(view)
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val item = getItem(position)
        holder.bind(item, expanded.contains(item.flag)) {
            toggle(item.flag, holder.bindingAdapterPosition)
        }
    }

    class ViewHolder(itemView: View) : RecyclerView.ViewHolder(itemView) {
        private val iconView: ImageView = itemView.findViewById(R.id.statusIcon)
        private val nameView: TextView = itemView.findViewById(R.id.checkName)
        private val descView: TextView = itemView.findViewById(R.id.checkDescription)
        private val detailView: TextView = itemView.findViewById(R.id.checkDetail)
        private val statusView: TextView = itemView.findViewById(R.id.checkStatus)
        private val chevron: ImageView = itemView.findViewById(R.id.expandChevron)
        private val rowRoot: View = itemView.findViewById(R.id.rowRoot)

        fun bind(result: DetectionResult, isExpanded: Boolean, onToggle: () -> Unit) {
            bindData(result, isExpanded)
            applyStatusStyle(result)
            bindExpansion(result, isExpanded, onToggle)
        }

        /*
         * The evidence is worth having but it is long, and twenty-three rows of
         * it makes the list unreadable at a glance. Collapsed by default, one
         * tap away, and rows with nothing to show are not tappable at all so a
         * tap never produces nothing.
         */
        private fun bindExpansion(
            result: DetectionResult,
            isExpanded: Boolean,
            onToggle: () -> Unit,
        ) {
            val hasEvidence = evidenceLines(result).isNotEmpty()
            if (!hasEvidence) {
                chevron.visibility = View.INVISIBLE
                rowRoot.setOnClickListener(null)
                rowRoot.isClickable = false
                rowRoot.contentDescription = null
                return
            }
            chevron.visibility = View.VISIBLE
            chevron.rotation = if (isExpanded) 180f else 0f
            rowRoot.isClickable = true
            rowRoot.setOnClickListener { onToggle() }
            rowRoot.contentDescription = itemView.context.getString(
                if (isExpanded) R.string.row_collapse else R.string.row_expand
            )
        }

        private fun evidenceLines(result: DetectionResult): List<String> = buildList {
            result.detail?.takeIf { it.isNotEmpty() }?.let { add(it) }
            result.reasons.forEach { add("\u2022 $it") }
        }

        private fun bindData(result: DetectionResult, isExpanded: Boolean) {
            nameView.text = result.name
            descView.text = result.description

            val lines = evidenceLines(result)
            if (lines.isEmpty() || !isExpanded) {
                detailView.visibility = View.GONE
            } else {
                detailView.visibility = View.VISIBLE
                detailView.text = lines.joinToString("\n")
            }
        }

        private fun applyStatusStyle(result: DetectionResult) {
            val ctx = itemView.context
            val (textRes, colorRes, iconRes) = when (result.state) {
                CheckState.DETECTED ->
                    Triple(R.string.result_status_detected, R.color.status_fail, R.drawable.ic_warning)

                // A generic badge: several rows use this state and the
                // revocation-specific wording was wrong on most of them. Each
                // row's detail says what was actually observed.
                CheckState.INFORMATIONAL ->
                    Triple(R.string.result_status_reported, R.color.status_warn, R.drawable.ic_warning)

                // Tried and reached no verdict, or never ran at all. Either way
                // it is not a pass, so it does not get the green tick.
                CheckState.UNVERIFIABLE, CheckState.SKIPPED ->
                    Triple(R.string.result_status_unverified, R.color.status_warn, R.drawable.ic_info)

                // Needs privilege the app does not have, or a platform surface
                // this device does not expose. Neither reads as a pass.
                CheckState.NOT_OBSERVABLE ->
                    Triple(R.string.result_status_unobservable, R.color.text_secondary, R.drawable.ic_info)

                CheckState.CLEAN ->
                    Triple(R.string.result_status_pass, R.color.status_pass, R.drawable.ic_check)
            }
            statusView.setText(textRes)
            val color = ContextCompat.getColor(ctx, colorRes)
            statusView.setTextColor(color)
            iconView.setImageResource(iconRes)
            iconView.setColorFilter(color)
        }
    }

    private companion object {
        val DIFF = object : DiffUtil.ItemCallback<DetectionResult>() {
            override fun areItemsTheSame(old: DetectionResult, new: DetectionResult) =
                old.flag == new.flag
            override fun areContentsTheSame(old: DetectionResult, new: DetectionResult) =
                old == new
        }
    }
}
