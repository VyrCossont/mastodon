class AddFullTextIndexToStatuses < ActiveRecord::Migration[6.1]
  disable_ddl_transaction!

  def change
    add_index :statuses,
              "(to_tsvector('english', spoiler_text) || to_tsvector('english', text))",
              name: 'index_statuses_full_text',
              where: 'deleted_at is null and reblog_of_id is null and visibility in (%{public}, %{unlisted})' %
                Status.visibilities.symbolize_keys,
              algorithm: :concurrently,
              using: 'gin'
  end
end
