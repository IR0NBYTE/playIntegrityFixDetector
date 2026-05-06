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
            applyStatusStyle(result.detected)
        }

        private fun bindData(result: DetectionResult) {
            nameView.text = result.name
            descView.text = result.description
        }

        private fun applyStatusStyle(detected: Boolean) {
            val ctx = itemView.context
            val (textRes, colorRes, iconRes) = if (detected) {
                Triple(R.string.result_status_detected, R.color.status_fail, R.drawable.ic_warning)
            } else {
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
