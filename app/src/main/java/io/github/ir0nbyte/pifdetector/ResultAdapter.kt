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

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_detection_result, parent, false)
        return ViewHolder(view)
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        holder.bind(getItem(position))
    }

    class ViewHolder(itemView: View) : RecyclerView.ViewHolder(itemView) {
        private val iconView: ImageView = itemView.findViewById(R.id.statusIcon)
        private val nameView: TextView = itemView.findViewById(R.id.checkName)
        private val descView: TextView = itemView.findViewById(R.id.checkDescription)
        private val statusView: TextView = itemView.findViewById(R.id.checkStatus)

        fun bind(result: DetectionResult) {
            bindData(result)
            applyStatusStyle(result)
        }

        private fun bindData(result: DetectionResult) {
            nameView.text = result.name
            descView.text = result.description
        }

        /*
         * Three states, not two. A privileged-only check that did not fire has
         * not "passed" -- an unprivileged app cannot see what it looks for, so
         * showing it green would claim coverage the sandbox forbids. It still
         * renders as DETECTED when it does fire, which happens when the app runs
         * with root/adb.
         */
        private fun applyStatusStyle(result: DetectionResult) {
            val ctx = itemView.context
            val (textRes, colorRes, iconRes) = when {
                result.detected ->
                    Triple(R.string.result_status_detected, R.color.status_fail, R.drawable.ic_warning)
                result.privilegedOnly ->
                    Triple(R.string.result_status_unobservable, R.color.text_secondary, R.drawable.ic_info)
                else ->
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
