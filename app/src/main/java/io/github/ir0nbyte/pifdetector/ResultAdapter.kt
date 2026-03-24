package io.github.ir0nbyte.pifdetector

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ImageView
import android.widget.TextView
import androidx.core.content.ContextCompat
import androidx.recyclerview.widget.RecyclerView

class ResultAdapter : RecyclerView.Adapter<ResultAdapter.ViewHolder>() {

    private var results: List<DetectionResult> = emptyList()

    fun submitResults(newResults: List<DetectionResult>) {
        results = newResults
        notifyDataSetChanged()
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_detection_result, parent, false)
        return ViewHolder(view)
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        holder.bind(results[position])
    }

    override fun getItemCount(): Int = results.size

    class ViewHolder(itemView: View) : RecyclerView.ViewHolder(itemView) {
        private val iconView: ImageView = itemView.findViewById(R.id.statusIcon)
        private val nameView: TextView = itemView.findViewById(R.id.checkName)
        private val descView: TextView = itemView.findViewById(R.id.checkDescription)
        private val statusView: TextView = itemView.findViewById(R.id.checkStatus)

        fun bind(result: DetectionResult) {
            nameView.text = result.name
            descView.text = result.description

            if (result.detected) {
                statusView.text = "DETECTED"
                statusView.setTextColor(ContextCompat.getColor(itemView.context, R.color.status_fail))
                iconView.setImageResource(R.drawable.ic_warning)
                iconView.setColorFilter(ContextCompat.getColor(itemView.context, R.color.status_fail))
            } else {
                statusView.text = "PASS"
                statusView.setTextColor(ContextCompat.getColor(itemView.context, R.color.status_pass))
                iconView.setImageResource(R.drawable.ic_check)
                iconView.setColorFilter(ContextCompat.getColor(itemView.context, R.color.status_pass))
            }
        }
    }
}
